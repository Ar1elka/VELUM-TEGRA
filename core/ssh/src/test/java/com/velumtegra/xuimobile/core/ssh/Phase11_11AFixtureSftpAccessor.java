package com.velumtegra.xuimobile.core.ssh;

import java.io.IOException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collections;
import java.util.Map;
import java.util.NavigableMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.apache.sshd.sftp.server.SftpFileSystemAccessor;
import org.apache.sshd.sftp.server.SftpSubsystemProxy;

/** Test-only Windows-portable SFTP attribute overlay for Phase 11.11A. */
final class Phase11_11AFixtureSftpAccessor implements SftpFileSystemAccessor {
    private final ConcurrentMap<String, ConcurrentMap<String, Object>> overlays = new ConcurrentHashMap<>();

    void capture(Path path, Map<String, ?> attrs) {
        ConcurrentMap<String, Object> overlay = overlays.computeIfAbsent(key(path), ignored -> new ConcurrentHashMap<>());
        copyIfPresent(attrs, overlay, "uid");
        copyIfPresent(attrs, overlay, "gid");
        copyIfPresent(attrs, overlay, "permissions");
    }

    private static void copyIfPresent(Map<String, ?> source, Map<String, Object> target, String name) {
        Object value = source.get(name);
        if (value != null) {
            target.put(name, value);
        }
    }

    @Override
    public NavigableMap<String, Object> resolveReportedFileAttributes(
            SftpSubsystemProxy subsystem,
            Path file,
            int flags,
            NavigableMap<String, Object> attrs,
            LinkOption... options) throws IOException {
        Map<String, Object> overlay = overlays.get(key(file));
        if (overlay != null) {
            attrs.putAll(overlay);
        }
        Path name = file.getFileName();
        if (name != null && "symlink-root".equals(name.toString())) {
            attrs.put("isRegularFile", Boolean.FALSE);
            attrs.put("isDirectory", Boolean.FALSE);
            attrs.put("isSymbolicLink", Boolean.TRUE);
            attrs.putIfAbsent("permissions", Collections.<PosixFilePermission>emptySet());
        }
        return attrs;
    }

    private static String key(Path path) {
        return path.normalize().toString().replace('\\', '/');
    }
}
