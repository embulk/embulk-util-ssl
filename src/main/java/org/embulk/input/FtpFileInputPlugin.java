package org.embulk.input;

import java.util.List;
import java.util.ArrayList;
import java.util.Collections;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.InputStream;
import java.nio.channels.Channels;
import org.slf4j.Logger;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import com.google.common.collect.ImmutableList;
import com.google.common.base.Optional;
import com.google.common.base.Throwables;
import com.google.common.base.Function;
import it.sauronsoftware.ftp4j.FTPClient;
import it.sauronsoftware.ftp4j.FTPFile;
import it.sauronsoftware.ftp4j.FTPConnector;
import it.sauronsoftware.ftp4j.FTPCommunicationListener;
import it.sauronsoftware.ftp4j.FTPDataTransferListener;
import it.sauronsoftware.ftp4j.FTPException;
import it.sauronsoftware.ftp4j.FTPIllegalReplyException;
import it.sauronsoftware.ftp4j.FTPDataTransferException;
import it.sauronsoftware.ftp4j.FTPAbortedException;
import it.sauronsoftware.ftp4j.FTPListParseException;
import org.embulk.config.CommitReport;
import org.embulk.config.Config;
import org.embulk.config.ConfigInject;
import org.embulk.config.ConfigDefault;
import org.embulk.config.ConfigDiff;
import org.embulk.config.ConfigSource;
import org.embulk.config.Task;
import org.embulk.config.TaskSource;
import org.embulk.spi.BufferAllocator;
import org.embulk.spi.Exec;
import org.embulk.spi.FileInputPlugin;
import org.embulk.spi.TransactionalFileInput;
import org.embulk.spi.util.InputStreamFileInput;
import org.embulk.input.ftp.BlockingTransfer;
import org.embulk.input.ftp.RetryableInputStream;
import org.embulk.input.ftp.RetryExecutor.Retryable;
import org.embulk.input.ftp.RetryExecutor.RetryGiveupException;
import static org.embulk.input.ftp.RetryExecutor.retryExecutor;

public class FtpFileInputPlugin
        implements FileInputPlugin
{
    private final Logger log = Exec.getLogger(FtpFileInputPlugin.class);

    public interface PluginTask
            extends Task
    {
        @Config("path_prefix")
        public String getPathPrefix();

        @Config("last_path")
        @ConfigDefault("null")
        public Optional<String> getLastPath();

        @Config("host")
        public String getHost();

        @Config("port")
        @ConfigDefault("21")
        public int getPort();

        @Config("user")
        @ConfigDefault("null")
        public Optional<String> getUser();

        @Config("password")
        @ConfigDefault("null")
        public Optional<String> getPassword();

        @Config("passive_mode")
        @ConfigDefault("true")
        public boolean getPassiveMode();

        //@Config("ascii_mode")
        //@ConfigDefault("false")
        //public boolean getAsciiMode();

        public List<String> getFiles();
        public void setFiles(List<String> files);

        @ConfigInject
        public BufferAllocator getBufferAllocator();
    }

    @Override
    public ConfigDiff transaction(ConfigSource config, FileInputPlugin.Control control)
    {
        PluginTask task = config.loadConfig(PluginTask.class);

        // list files recursively
        task.setFiles(listFiles(task));

        // TODO what if task.getFiles().isEmpty()?

        // number of processors is same with number of files
        return resume(task.dump(), task.getFiles().size(), control);
    }

    @Override
    public ConfigDiff resume(TaskSource taskSource,
            int taskCount,
            FileInputPlugin.Control control)
    {
        PluginTask task = taskSource.loadTask(PluginTask.class);

        control.run(taskSource, taskCount);

        // build next config
        ConfigDiff configDiff = Exec.newConfigDiff();

        // last_path
        if (task.getFiles().isEmpty()) {
            // keep the last value
            if (task.getLastPath().isPresent()) {
                configDiff.set("last_path", task.getLastPath().get());
            }
        } else {
            List<String> files = new ArrayList<String>(task.getFiles());
            Collections.sort(files);
            configDiff.set("last_path", files.get(files.size() - 1));
        }

        return configDiff;
    }

    @Override
    public void cleanup(TaskSource taskSource,
            int taskCount,
            List<CommitReport> successCommitReports)
    {
        // do nothing
    }

    private FTPClient newFTPClient(PluginTask task)
    {
        FTPClient client = new FTPClient();
        try {
            // TODO SSL

            client.addCommunicationListener(new LoggingCommunicationListner());
            //client.setAutoNoopTimeout(TDConstants.TD_RESULT_FTP_CONTROL_KEEPALIVE_INTERVAL);

            FTPConnector con = client.getConnector();
            //con.setConnectionTimeout(TDConstants.TD_RESULT_FTP_CONNECTION_TIMEOUT);
            //con.setReadTimeout(TDConstants.TD_RESULT_FTP_READ_TIMEOUT);
            //con.setCloseTimeout(TDConstants.TD_RESULT_FTP_READ_TIMEOUT);

            // for commons-net client
            //client.setControlKeepAliveTimeout
            //client.setConnectTimeout
            //client.setSoTimeout
            //client.setDataTimeout
            //client.setAutodetectUTF8

            log.info("Connecting to "+task.getHost());
            client.connect(task.getHost(), task.getPort());

            if (task.getUser().isPresent()) {
                log.info("Logging in with user "+task.getUser());
                client.login(task.getUser().get(), task.getPassword().or(""));
            }

            log.info("Using passive mode");
            client.setPassive(task.getPassiveMode());

            //if (task.getAsciiMode()) {
            //    log.info("Using ASCII mode");
            //    client.setType(FTPClient.TYPE_TEXTUAL);
            //} else {
            //    log.info("Using binary mode");
            //    client.setType(FTPClient.TYPE_BINARY);
            //}
            log.info("Using binary mode");
            client.setType(FTPClient.TYPE_BINARY);

            if (client.isCompressionSupported()) {
                log.info("Using MODE Z compression");
                client.setCompressionEnabled(true);
            }

            FTPClient connected = client;
            client = null;
            return connected;

        } catch (FTPException ex) {
            log.info("FTP command failed: "+ex.getCode()+" "+ex.getMessage());
            throw Throwables.propagate(ex);

        } catch (FTPIllegalReplyException ex) {
            log.info("FTP protocol error");
            throw Throwables.propagate(ex);

        } catch (IOException ex) {
            log.info("FTP network error: "+ex);
            throw Throwables.propagate(ex);

        } finally {
            if (client != null) {
                disconnectClient(client);
            }
        }
    }

    static void disconnectClient(FTPClient client)
    {
        if (client.isConnected()) {
            try {
                client.disconnect(false);
            } catch (FTPException ex) {
                // do nothing
            } catch (FTPIllegalReplyException ex) {
                // do nothing
            } catch (IOException ex) {
                // do nothing
            }
        }
    }

    private List<String> listFiles(PluginTask task)
    {
        FTPClient client = newFTPClient(task);
        try {
            return listFilesByPrefix(client, task.getPathPrefix(), task.getLastPath());
        } finally {
            disconnectClient(client);
        }
    }

    public List<String> listFilesByPrefix(FTPClient client,
            String prefix, Optional<String> lastPath)
    {
        String directory;
        String fileNamePrefix;
        if (prefix.isEmpty()) {
            directory = "";
            fileNamePrefix = "";
        } else {
            int pos = prefix.lastIndexOf("/");
            if (pos < 0) {
                directory = prefix;
                fileNamePrefix = "";
            } else {
                directory = prefix.substring(0, pos);
                fileNamePrefix = prefix.substring(pos + 1);
            }
        }

        ImmutableList.Builder<String> builder = ImmutableList.builder();

        try {
            String currentDirectory = client.currentDirectory();
            if (!directory.isEmpty()) {
                client.changeDirectory(directory);
            }
            log.info("Listing ftp files at directory '{}' filtering filename by prefix '{}'", directory.isEmpty() ? currentDirectory : directory, fileNamePrefix);

            for (FTPFile file : client.list()) {
                if (file.getName().startsWith(fileNamePrefix)) {
                    listFilesRecursive(client, currentDirectory, file, builder);
                }
            }

        } catch (FTPListParseException ex) {
            log.info("FTP listing files failed");
            throw Throwables.propagate(ex);

        } catch (FTPAbortedException ex) {
            log.info("FTP listing files failed");
            throw Throwables.propagate(ex);

        } catch (FTPDataTransferException ex) {
            log.info("FTP data transfer failed");
            throw Throwables.propagate(ex);

        } catch (FTPException ex) {
            log.info("FTP command failed: "+ex.getCode()+" "+ex.getMessage());
            throw Throwables.propagate(ex);

        } catch (FTPIllegalReplyException ex) {
            log.info("FTP protocol error");
            throw Throwables.propagate(ex);

        } catch (IOException ex) {
            log.info("FTP network error: "+ex);
            throw Throwables.propagate(ex);
        }

        return builder.build();
    }

    private void listFilesRecursive(FTPClient client,
            String directoryPath, FTPFile file,
            ImmutableList.Builder<String> builder)
        throws IOException, FTPException, FTPIllegalReplyException, FTPDataTransferException, FTPAbortedException, FTPListParseException
    {
        String path = directoryPath + "/" + file.getName();

        switch (file.getType()) {
        case FTPFile.TYPE_FILE:
            builder.add(path);
            break;
        case FTPFile.TYPE_DIRECTORY:
            for (FTPFile subFile : client.list()) {
                listFilesRecursive(client, path, subFile, builder);
            }
            break;
        case FTPFile.TYPE_LINK:
            // TODO
        }
    }

    @Override
    public TransactionalFileInput open(TaskSource taskSource, int taskIndex)
    {
        PluginTask task = taskSource.loadTask(PluginTask.class);
        return new FtpFileInput(task, taskIndex);
    }

    InputStream startDownload(final FTPClient client, final String path,
            final long offset, ExecutorService executor)
    {
        BlockingTransfer t = BlockingTransfer.submit(executor,
                new Function<BlockingTransfer, Runnable>()
                {
                    public Runnable apply(final BlockingTransfer transfer)
                    {
                        return new Runnable() {
                            public void run()
                            {
                                try {
                                    client.download(path, Channels.newOutputStream(transfer.getWriterChannel()), offset, new LoggingTransferListener());

                                } catch (FTPException ex) {
                                    log.info("FTP command failed: "+ex.getCode()+" "+ex.getMessage());
                                    throw Throwables.propagate(ex);

                                } catch (FTPDataTransferException ex) {
                                    log.info("FTP data transfer failed");
                                    throw Throwables.propagate(ex);

                                } catch (FTPAbortedException ex) {
                                    log.info("FTP listing files failed");
                                    throw Throwables.propagate(ex);

                                } catch (FTPIllegalReplyException ex) {
                                    log.info("FTP protocol error");
                                    throw Throwables.propagate(ex);

                                } catch (IOException ex) {
                                    throw Throwables.propagate(ex);

                                } finally {
                                    try {
                                        transfer.getWriterChannel().close();
                                    } catch (IOException ex) {
                                        throw new RuntimeException(ex);
                                    }
                                }
                            }
                        };
                    }
                });
        return Channels.newInputStream(t.getReaderChannel());
    }

    private class LoggingCommunicationListner
            implements FTPCommunicationListener
    {
        public void received(String statement)
        {
            log.info("< "+statement);
        }

        public void sent(String statement)
        {
            if (statement.startsWith("PASS")) {
                // don't show password
                return;
            }
            log.info("> "+statement);
        }
    }

    private class LoggingTransferListener
            implements FTPDataTransferListener
    {
        private static final long TRANSFER_NOTICE_BYTES = 100*1024*1024;

        private long totalTransfer;
        private long nextTransferNotice = TRANSFER_NOTICE_BYTES;

        public void started()
        {
            log.info("Transfer started");
        }

        public void transferred(int length)
        {
            totalTransfer += length;
            if (totalTransfer > nextTransferNotice) {
                log.info("Transferred "+totalTransfer+" bytes");
                nextTransferNotice = ((totalTransfer / TRANSFER_NOTICE_BYTES)+1) * TRANSFER_NOTICE_BYTES;
            }
        }

        public void completed()
        {
            log.info("Transfer completed "+totalTransfer+" bytes");
        }

        public void aborted()
        {
            log.info("Transfer aborted");
        }

        public void failed()
        {
            log.info("Transfer failed");
        }
    }

    private class FtpRetryableOpener
            implements RetryableInputStream.Opener
    {
        private final FTPClient client;
        private final ExecutorService executor;
        private final String path;

        public FtpRetryableOpener(FTPClient client, ExecutorService executor, String path)
        {
            this.client = client;
            this.executor = executor;
            this.path = path;
        }

        @Override
        public InputStream open(final long offset, final Exception exception) throws IOException
        {
            try {
                return retryExecutor()
                    .withRetryLimit(3)
                    .withInitialRetryWait(500)
                    .withMaxRetryWait(30*1000)
                    .runInterruptible(new Retryable<InputStream>() {
                        @Override
                        public InputStream call() throws InterruptedIOException
                        {
                            log.warn(String.format("FTP read failed. Retrying GET request with %,d bytes offset", offset), exception);
                            return startDownload(client, path, offset, executor);
                        }

                        @Override
                        public boolean isRetryableException(Exception exception)
                        {
                            return true;  // TODO
                        }

                        @Override
                        public void onRetry(Exception exception, int retryCount, int retryLimit, int retryWait)
                                throws RetryGiveupException
                        {
                            String message = String.format("FTP GET request failed. Retrying %d/%d after %d seconds. Message: %s",
                                    retryCount, retryLimit, retryWait/1000, exception.getMessage());
                            if (retryCount % 3 == 0) {
                                log.warn(message, exception);
                            } else {
                                log.warn(message);
                            }
                        }

                        @Override
                        public void onGiveup(Exception firstException, Exception lastException)
                                throws RetryGiveupException
                        {
                        }
                    });
            } catch (RetryGiveupException ex) {
                Throwables.propagateIfInstanceOf(ex.getCause(), IOException.class);
                throw Throwables.propagate(ex.getCause());
            } catch (InterruptedException ex) {
                throw new InterruptedIOException();
            }
        }
    }

    // TODO create single-file InputStreamFileInput utility
    private class SingleFileProvider
            implements InputStreamFileInput.Provider
    {
        private final FTPClient client;
        private final ExecutorService executor;
        private final String path;
        private boolean opened = false;

        public SingleFileProvider(PluginTask task, int taskIndex)
        {
            this.client = newFTPClient(task);
            this.executor = Executors.newCachedThreadPool(
                    new ThreadFactoryBuilder()
                        .setNameFormat("embulk-input-ftp-%d")
                        .setDaemon(true)
                        .build());
            this.path = task.getFiles().get(taskIndex);
        }

        @Override
        public InputStream openNext() throws IOException
        {
            if (opened) {
                return null;
            }
            opened = true;

            return new RetryableInputStream(
                    startDownload(client, path, 0L, executor),
                    new FtpRetryableOpener(client, executor, path));
        }

        @Override
        public void close()
        {
            executor.shutdownNow();
            disconnectClient(client);
        }
    }

    public class FtpFileInput
            extends InputStreamFileInput
            implements TransactionalFileInput
    {
        public FtpFileInput(PluginTask task, int taskIndex)
        {
            super(task.getBufferAllocator(), new SingleFileProvider(task, taskIndex));
        }

        public void abort() { }

        public CommitReport commit()
        {
            return Exec.newCommitReport();
        }

        @Override
        public void close() { }
    }
}
