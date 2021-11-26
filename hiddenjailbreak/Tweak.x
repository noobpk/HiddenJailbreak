#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Cephei/HBPreferences.h>
#import "Core/HJHook.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>
#include <spawn.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <sys/sysctl.h>
#include "Core/Utils/codesign.h"

static HiddenJailbreak *_hiddenjailbreak = nil;

static NSMutableDictionary *enum_path = nil;

static NSArray *dyld_array = nil;
static uint32_t dyld_array_count = 0;

static NSError *_error_file_not_found = nil;

static BOOL passthrough = NO;
static BOOL extra_compat = YES;

static void updateDyldArray(void) {
    dyld_array_count = 0;
    dyld_array = [_hiddenjailbreak generateDyldArray];
    dyld_array_count = (uint32_t) [dyld_array count];

    NSLog(@"generated dyld array (%d items)", dyld_array_count);
}

static void dyld_image_added(const struct mach_header *mh, intptr_t slide) {
    passthrough = YES;

    Dl_info info;
    int addr = dladdr(mh, &info);

    if(addr) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:info.dli_fname length:strlen(info.dli_fname)];

        if([_hiddenjailbreak isImageRestricted:path]) {
            void *handle = dlopen(info.dli_fname, RTLD_NOLOAD);

            if(handle) {
                dlclose(handle);

                NSLog(@"unloaded %s", info.dli_fname);
            }
        }
    }

    passthrough = NO;
}

// Stable Hooks
%group hook_libc
%hookf(int, access, const char *pathname, int mode) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        // workaround for tweaks not loading properly in Substrate
        if([_hiddenjailbreak useInjectCompatibilityMode]) {
            if([[path pathExtension] isEqualToString:@"plist"] && [path hasPrefix:@"/Library/MobileSubstrate"]) {
                return %orig;
            }
        }

        if([_hiddenjailbreak isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(char *, getenv, const char *name) {
    if(name) {
        NSString *env = [NSString stringWithUTF8String:name];

        if([env isEqualToString:@"DYLD_INSERT_LIBRARIES"]
        || [env isEqualToString:@"_MSSafeMode"]
        || [env isEqualToString:@"_SafeMode"]) {
            return NULL;
        }
    }

    return %orig;
}

%hookf(FILE *, fopen, const char *pathname, const char *mode) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];
        
        if([_hiddenjailbreak isPathRestricted:path]) {
            errno = ENOENT;
            return NULL;
        }
    }

    return %orig;
}

%hookf(FILE *, freopen, const char *pathname, const char *mode, FILE *stream) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_hiddenjailbreak isPathRestricted:path]) {
            fclose(stream);
            errno = ENOENT;
            return NULL;
        }
    }

    return %orig;
}

%hookf(int, stat, const char *pathname, struct stat *statbuf) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_hiddenjailbreak isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }

        // Maybe some filesize overrides?
        if(statbuf) {
            if([path isEqualToString:@"/bin"]) {
                int ret = %orig;

                if(ret == 0 && statbuf->st_size > 128) {
                    statbuf->st_size = 128;
                    return ret;
                }
            }
        }
    }

    return %orig;
}

%hookf(int, lstat, const char *pathname, struct stat *statbuf) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_hiddenjailbreak isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }

        // Maybe some filesize overrides?
        if(statbuf) {
            if([path isEqualToString:@"/Applications"]
            || [path isEqualToString:@"/usr/share"]
            || [path isEqualToString:@"/usr/libexec"]
            || [path isEqualToString:@"/usr/include"]
            || [path isEqualToString:@"/Library/Ringtones"]
            || [path isEqualToString:@"/Library/Wallpaper"]) {
                int ret = %orig;

                if(ret == 0 && (statbuf->st_mode & S_IFLNK) == S_IFLNK) {
                    statbuf->st_mode &= ~S_IFLNK;
                    return ret;
                }
            }

            if([path isEqualToString:@"/bin"]) {
                int ret = %orig;

                if(ret == 0 && statbuf->st_size > 128) {
                    statbuf->st_size = 128;
                    return ret;
                }
            }
        }
    }

    return %orig;
}

%hookf(int, fstatfs, int fd, struct statfs *buf) {
    int ret = %orig;

    if(ret == 0) {
        // Get path of dirfd.
        char path[PATH_MAX];

        if(fcntl(fd, F_GETPATH, path) != -1) {
            NSString *pathname = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

            if([_hiddenjailbreak isPathRestricted:pathname]) {
                errno = ENOENT;
                return -1;
            }

            pathname = [_hiddenjailbreak resolveLinkInPath:pathname];
            
            if(![pathname hasPrefix:@"/var"]
            && ![pathname hasPrefix:@"/private/var"]) {
                if(buf) {
                    // Ensure root fs is marked read-only.
                    buf->f_flags |= MNT_RDONLY | MNT_ROOTFS;
                    return ret;
                }
            } else {
                // Ensure var fs is marked NOSUID.
                buf->f_flags |= MNT_NOSUID | MNT_NODEV;
                return ret;
            }
        }
    }

    return ret;
}

%hookf(int, statfs, const char *path, struct statfs *buf) {
    int ret = %orig;

    if(ret == 0) {
        NSString *pathname = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if([_hiddenjailbreak isPathRestricted:pathname]) {
            errno = ENOENT;
            return -1;
        }

        pathname = [_hiddenjailbreak resolveLinkInPath:pathname];

        if(![pathname hasPrefix:@"/var"]
        && ![pathname hasPrefix:@"/private/var"]) {
            if(buf) {
                // Ensure root fs is marked read-only.
                buf->f_flags |= MNT_RDONLY | MNT_ROOTFS;
                return ret;
            }
        } else {
            // Ensure var fs is marked NOSUID.
            buf->f_flags |= MNT_NOSUID | MNT_NODEV;
            return ret;
        }
    }

    return ret;
}

%hookf(int, posix_spawn, pid_t *pid, const char *pathname, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_hiddenjailbreak isPathRestricted:path]) {
            return ENOENT;
        }
    }

    return %orig;
}

%hookf(int, posix_spawnp, pid_t *pid, const char *pathname, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_hiddenjailbreak isPathRestricted:path]) {
            return ENOENT;
        }
    }

    return %orig;
}

%hookf(char *, realpath, const char *pathname, char *resolved_path) {
    BOOL doFree = (resolved_path != NULL);
    NSString *path = nil;

    if(pathname) {
        path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_hiddenjailbreak isPathRestricted:path]) {
            errno = ENOENT;
            return NULL;
        }
    }

    char *ret = %orig;

    // Recheck resolved path.
    if(ret) {
        NSString *resolved_path_ns = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:ret length:strlen(ret)];

        if([_hiddenjailbreak isPathRestricted:resolved_path_ns]) {
            errno = ENOENT;

            // Free resolved_path if it was allocated by libc.
            if(doFree) {
                free(ret);
            }

            return NULL;
        }

        if(strcmp(ret, pathname) != 0) {
            // Possible symbolic link? Track it in HiddenJailbreak
            [_hiddenjailbreak addLinkFromPath:path toPath:resolved_path_ns];
        }
    }

    return ret;
}

%hookf(int, symlink, const char *path1, const char *path2) {
    NSString *path1_ns = nil;
    NSString *path2_ns = nil;

    if(path1 && path2) {
        path1_ns = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path1 length:strlen(path1)];
        path2_ns = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path2 length:strlen(path2)];

        if([_hiddenjailbreak isPathRestricted:path1_ns] || [_hiddenjailbreak isPathRestricted:path2_ns]) {
            errno = ENOENT;
            return -1;
        }
    }

    int ret = %orig;

    if(ret == 0) {
        // Track this symlink in HiddenJailbreak
        [_hiddenjailbreak addLinkFromPath:path1_ns toPath:path2_ns];
    }

    return ret;
}

%hookf(int, rename, const char *oldname, const char *newname) {
    NSString *oldname_ns = nil;
    NSString *newname_ns = nil;

    if(oldname && newname) {
        oldname_ns = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:oldname length:strlen(oldname)];
        newname_ns = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:newname length:strlen(newname)];

        if([_hiddenjailbreak isPathRestricted:oldname_ns] || [_hiddenjailbreak isPathRestricted:newname_ns]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, remove, const char *filename) {
    if(filename) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:filename length:strlen(filename)];

        if([_hiddenjailbreak isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, unlink, const char *pathname) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_hiddenjailbreak isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, unlinkat, int dirfd, const char *pathname, int flags) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if(![path isAbsolutePath]) {
            // Get path of dirfd.
            char dirfdpath[PATH_MAX];
        
            if(fcntl(dirfd, F_GETPATH, dirfdpath) != -1) {
                NSString *dirfd_path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:dirfdpath length:strlen(dirfdpath)];
                path = [dirfd_path stringByAppendingPathComponent:path];
            }
        }
        
        if([_hiddenjailbreak isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, rmdir, const char *pathname) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_hiddenjailbreak isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, chdir, const char *pathname) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_hiddenjailbreak isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, fchdir, int fd) {
    char dirfdpath[PATH_MAX];

    if(fcntl(fd, F_GETPATH, dirfdpath) != -1) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:dirfdpath length:strlen(dirfdpath)];

        if([_hiddenjailbreak isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, link, const char *path1, const char *path2) {
    NSString *path1_ns = nil;
    NSString *path2_ns = nil;

    if(path1 && path2) {
        path1_ns = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path1 length:strlen(path1)];
        path2_ns = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path2 length:strlen(path2)];

        if([_hiddenjailbreak isPathRestricted:path1_ns] || [_hiddenjailbreak isPathRestricted:path2_ns]) {
            errno = ENOENT;
            return -1;
        }
    }

    int ret = %orig;

    if(ret == 0) {
        // Track this symlink in HiddenJailbreak
        [_hiddenjailbreak addLinkFromPath:path1_ns toPath:path2_ns];
    }

    return ret;
}

%hookf(int, fstatat, int dirfd, const char *pathname, struct stat *buf, int flags) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if(![path isAbsolutePath]) {
            // Get path of dirfd.
            char dirfdpath[PATH_MAX];
        
            if(fcntl(dirfd, F_GETPATH, dirfdpath) != -1) {
                NSString *dirfd_path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:dirfdpath length:strlen(dirfdpath)];
                path = [dirfd_path stringByAppendingPathComponent:path];
            }
        }
        
        if([_hiddenjailbreak isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, faccessat, int dirfd, const char *pathname, int mode, int flags) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if(![path isAbsolutePath]) {
            // Get path of dirfd.
            char dirfdpath[PATH_MAX];
        
            if(fcntl(dirfd, F_GETPATH, dirfdpath) != -1) {
                NSString *dirfd_path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:dirfdpath length:strlen(dirfdpath)];
                path = [dirfd_path stringByAppendingPathComponent:path];
            }
        }
        
        if([_hiddenjailbreak isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    return %orig;
}

%hookf(int, chroot, const char *dirname) {
    if(dirname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:dirname length:strlen(dirname)];

        if([_hiddenjailbreak isPathRestricted:path]) {
            errno = ENOENT;
            return -1;
        }
    }

    int ret = %orig;

    if(ret == 0) {
        [_hiddenjailbreak addLinkFromPath:@"/" toPath:[[NSFileManager defaultManager] stringWithFileSystemRepresentation:dirname length:strlen(dirname)]];
    }

    return ret;
}
%end

%group hook_libc_inject
%hookf(int, fstat, int fd, struct stat *buf) {
    // Get path of dirfd.
    char fdpath[PATH_MAX];

    if(fcntl(fd, F_GETPATH, fdpath) != -1) {
        NSString *fd_path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:fdpath length:strlen(fdpath)];
        
        if([_hiddenjailbreak isPathRestricted:fd_path]) {
            errno = EBADF;
            return -1;
        }

        if(buf) {
            if([fd_path isEqualToString:@"/bin"]) {
                int ret = %orig;

                if(ret == 0 && buf->st_size > 128) {
                    buf->st_size = 128;
                    return ret;
                }
            }
        }
    }

    return %orig;
}
%end

%group hook_dlopen_inject
%hookf(void *, dlopen, const char *path, int mode) {
    if(!passthrough && path) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if([_hiddenjailbreak isImageRestricted:image_name]) {
            return NULL;
        }
    }

    return %orig;
}
%end

%group hook_NSFileHandle
// #include "Hooks/Stable/NSFileHandle.xm"
%hook NSFileHandle
+ (instancetype)fileHandleForReadingAtPath:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)fileHandleForReadingFromURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:url]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)fileHandleForWritingAtPath:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)fileHandleForWritingToURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:url]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)fileHandleForUpdatingAtPath:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)fileHandleForUpdatingURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:url]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}
%end
%end

%group hook_NSFileManager
%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path manager:self]) {
        return NO;
    }

    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if([_hiddenjailbreak isPathRestricted:path manager:self]) {
        return NO;
    }

    return %orig;
}

- (BOOL)isReadableFileAtPath:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path manager:self]) {
        return NO;
    }

    return %orig;
}

- (BOOL)isWritableFileAtPath:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path manager:self]) {
        return NO;
    }

    return %orig;
}

- (BOOL)isDeletableFileAtPath:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path manager:self]) {
        return NO;
    }

    return %orig;
}

- (BOOL)isExecutableFileAtPath:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path manager:self]) {
        return NO;
    }

    return %orig;
}

- (NSURL *)URLForDirectory:(NSSearchPathDirectory)directory inDomain:(NSSearchPathDomainMask)domain appropriateForURL:(NSURL *)url create:(BOOL)shouldCreate error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:url manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

- (NSArray<NSURL *> *)URLsForDirectory:(NSSearchPathDirectory)directory inDomains:(NSSearchPathDomainMask)domainMask {
    NSArray *ret = %orig;

    if(ret) {
        NSMutableArray *toRemove = [NSMutableArray new];
        NSMutableArray *filtered = [ret mutableCopy];

        for(NSURL *url in filtered) {
            if([_hiddenjailbreak isURLRestricted:url manager:self]) {
                [toRemove addObject:url];
            }
        }

        [filtered removeObjectsInArray:toRemove];
        ret = [filtered copy];
    }

    return ret;
}

- (BOOL)isUbiquitousItemAtURL:(NSURL *)url {
    if([_hiddenjailbreak isURLRestricted:url manager:self]) {
        return NO;
    }

    return %orig;
}

- (BOOL)setUbiquitous:(BOOL)flag itemAtURL:(NSURL *)url destinationURL:(NSURL *)destinationURL error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:url manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)replaceItemAtURL:(NSURL *)originalItemURL withItemAtURL:(NSURL *)newItemURL backupItemName:(NSString *)backupItemName options:(NSFileManagerItemReplacementOptions)options resultingItemURL:(NSURL * _Nullable *)resultingURL error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:originalItemURL manager:self] || [_hiddenjailbreak isURLRestricted:newItemURL manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (NSArray<NSURL *> *)contentsOfDirectoryAtURL:(NSURL *)url includingPropertiesForKeys:(NSArray<NSURLResourceKey> *)keys options:(NSDirectoryEnumerationOptions)mask error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:url manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    // Filter array.
    NSMutableArray *filtered_ret = nil;
    NSArray *ret = %orig;

    if(ret) {
        filtered_ret = [NSMutableArray new];

        for(NSURL *ret_url in ret) {
            if(![_hiddenjailbreak isURLRestricted:ret_url manager:self]) {
                [filtered_ret addObject:ret_url];
            }
        }
    }

    return ret ? [filtered_ret copy] : ret;
}

- (NSArray<NSString *> *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:path manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    // Filter array.
    NSMutableArray *filtered_ret = nil;
    NSArray *ret = %orig;

    if(ret) {
        filtered_ret = [NSMutableArray new];

        for(NSString *ret_path in ret) {
            // Ensure absolute path for path.
            if(![_hiddenjailbreak isPathRestricted:[path stringByAppendingPathComponent:ret_path] manager:self]) {
                [filtered_ret addObject:ret_path];
            }
        }
    }

    return ret ? [filtered_ret copy] : ret;
}

- (NSDirectoryEnumerator<NSURL *> *)enumeratorAtURL:(NSURL *)url includingPropertiesForKeys:(NSArray<NSURLResourceKey> *)keys options:(NSDirectoryEnumerationOptions)mask errorHandler:(BOOL (^)(NSURL *url, NSError *error))handler {
    if([_hiddenjailbreak isURLRestricted:url manager:self]) {
        return %orig([NSURL fileURLWithPath:@"/.file"], keys, mask, handler);
    }

    return %orig;
}

- (NSDirectoryEnumerator<NSString *> *)enumeratorAtPath:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path manager:self]) {
        return %orig(@"/.file");
    }

    NSDirectoryEnumerator *ret = %orig;

    if(ret && enum_path) {
        // Store this path.
        [enum_path setObject:path forKey:[NSValue valueWithNonretainedObject:ret]];
    }

    return ret;
}

- (NSArray<NSString *> *)subpathsOfDirectoryAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:path manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    // Filter array.
    NSMutableArray *filtered_ret = nil;
    NSArray *ret = %orig;

    if(ret) {
        filtered_ret = [NSMutableArray new];

        for(NSString *ret_path in ret) {
            // Ensure absolute path for path.
            if(![_hiddenjailbreak isPathRestricted:[path stringByAppendingPathComponent:ret_path] manager:self]) {
                [filtered_ret addObject:ret_path];
            }
        }
    }

    return ret ? [filtered_ret copy] : ret;
}

- (NSArray<NSString *> *)subpathsAtPath:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path manager:self]) {
        return nil;
    }

    // Filter array.
    NSMutableArray *filtered_ret = nil;
    NSArray *ret = %orig;

    if(ret) {
        filtered_ret = [NSMutableArray new];

        for(NSString *ret_path in ret) {
            // Ensure absolute path for path.
            if(![_hiddenjailbreak isPathRestricted:[path stringByAppendingPathComponent:ret_path] manager:self]) {
                [filtered_ret addObject:ret_path];
            }
        }
    }

    return ret ? [filtered_ret copy] : ret;
}

- (BOOL)copyItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:srcURL manager:self] || [_hiddenjailbreak isURLRestricted:dstURL manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)copyItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:srcPath manager:self] || [_hiddenjailbreak isPathRestricted:dstPath manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)moveItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:srcURL manager:self] || [_hiddenjailbreak isURLRestricted:dstURL manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)moveItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:srcPath manager:self] || [_hiddenjailbreak isPathRestricted:dstPath manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (NSArray<NSString *> *)componentsToDisplayForPath:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path manager:self]) {
        return nil;
    }

    return %orig;
}

- (NSString *)displayNameAtPath:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path manager:self]) {
        return path;
    }

    return %orig;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfItemAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:path manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfFileSystemForPath:(NSString *)path error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:path manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

- (BOOL)setAttributes:(NSDictionary<NSFileAttributeKey, id> *)attributes ofItemAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:path manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (NSData *)contentsAtPath:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path manager:self]) {
        return nil;
    }

    return %orig;
}

- (BOOL)contentsEqualAtPath:(NSString *)path1 andPath:(NSString *)path2 {
    if([_hiddenjailbreak isPathRestricted:path1] || [_hiddenjailbreak isPathRestricted:path2]) {
        return NO;
    }

    return %orig;
}

- (BOOL)getRelationship:(NSURLRelationship *)outRelationship ofDirectoryAtURL:(NSURL *)directoryURL toItemAtURL:(NSURL *)otherURL error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:directoryURL manager:self] || [_hiddenjailbreak isURLRestricted:otherURL manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)getRelationship:(NSURLRelationship *)outRelationship ofDirectory:(NSSearchPathDirectory)directory inDomain:(NSSearchPathDomainMask)domainMask toItemAtURL:(NSURL *)otherURL error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:otherURL manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)changeCurrentDirectoryPath:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path manager:self]) {
        return NO;
    }

    return %orig;
}

- (BOOL)createSymbolicLinkAtURL:(NSURL *)url withDestinationURL:(NSURL *)destURL error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:url manager:self] || [_hiddenjailbreak isURLRestricted:destURL manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    BOOL ret = %orig;

    if(ret) {
        // Track this symlink in HiddenJailbreak
        [_hiddenjailbreak addLinkFromPath:[url path] toPath:[destURL path]];
    }

    return ret;
}

- (BOOL)createSymbolicLinkAtPath:(NSString *)path withDestinationPath:(NSString *)destPath error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:path] || [_hiddenjailbreak isPathRestricted:destPath]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    BOOL ret = %orig;

    if(ret) {
        // Track this symlink in HiddenJailbreak
        [_hiddenjailbreak addLinkFromPath:path toPath:destPath];
    }

    return ret;
}

- (BOOL)linkItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:srcURL manager:self] || [_hiddenjailbreak isURLRestricted:dstURL manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    BOOL ret = %orig;

    if(ret) {
        // Track this symlink in HiddenJailbreak
        [_hiddenjailbreak addLinkFromPath:[srcURL path] toPath:[dstURL path]];
    }

    return ret;
}

- (BOOL)linkItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:srcPath manager:self] || [_hiddenjailbreak isPathRestricted:dstPath manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    BOOL ret = %orig;

    if(ret) {
        // Track this symlink in HiddenJailbreak
        [_hiddenjailbreak addLinkFromPath:srcPath toPath:dstPath];
    }

    return ret;
}

- (NSString *)destinationOfSymbolicLinkAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:path manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    NSString *ret = %orig;

    if(ret) {
        // Track this symlink in HiddenJailbreak
        [_hiddenjailbreak addLinkFromPath:path toPath:ret];
    }

    return ret;
}
%end
%end

%group hook_NSEnumerator
%hook NSDirectoryEnumerator
- (id)nextObject {
    id ret = nil;
    NSString *parent = nil;

    if(enum_path) {
        parent = enum_path[[NSValue valueWithNonretainedObject:self]];
    }

    while((ret = %orig)) {
        if([ret isKindOfClass:[NSURL class]]) {
            if(![_hiddenjailbreak isURLRestricted:ret]) {
                break;
            }
        }

        if([ret isKindOfClass:[NSString class]]) {
            if(parent) {
                NSString *path = [parent stringByAppendingPathComponent:ret];

                if(![_hiddenjailbreak isPathRestricted:path]) {
                    break;
                }
            } else {
                break;
            }
        }
    }

    return ret;
}
%end
%end

%group hook_NSFileWrapper
%hook NSFileWrapper
- (instancetype)initWithURL:(NSURL *)url options:(NSFileWrapperReadingOptions)options error:(NSError * _Nullable *)outError {
    if([_hiddenjailbreak isURLRestricted:url]) {
        if(outError) {
            *outError = _error_file_not_found;
        }

        return 0;
    }

    return %orig;
}

- (instancetype)initSymbolicLinkWithDestinationURL:(NSURL *)url {
    if([_hiddenjailbreak isURLRestricted:url]) {
        return 0;
    }

    return %orig;
}

- (BOOL)matchesContentsOfURL:(NSURL *)url {
    if([_hiddenjailbreak isURLRestricted:url]) {
        return NO;
    }

    return %orig;
}

- (BOOL)readFromURL:(NSURL *)url options:(NSFileWrapperReadingOptions)options error:(NSError * _Nullable *)outError {
    if([_hiddenjailbreak isURLRestricted:url]) {
        if(outError) {
            *outError = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url options:(NSFileWrapperWritingOptions)options originalContentsURL:(NSURL *)originalContentsURL error:(NSError * _Nullable *)outError {
    if([_hiddenjailbreak isURLRestricted:url]) {
        if(outError) {
            *outError = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}
%end
%end

%group hook_NSFileVersion
%hook NSFileVersion
+ (NSFileVersion *)currentVersionOfItemAtURL:(NSURL *)url {
    if([_hiddenjailbreak isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

+ (NSArray<NSFileVersion *> *)otherVersionsOfItemAtURL:(NSURL *)url {
    if([_hiddenjailbreak isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

+ (NSFileVersion *)versionOfItemAtURL:(NSURL *)url forPersistentIdentifier:(id)persistentIdentifier {
    if([_hiddenjailbreak isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

+ (NSURL *)temporaryDirectoryURLForNewVersionOfItemAtURL:(NSURL *)url {
    if([_hiddenjailbreak isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

+ (NSFileVersion *)addVersionOfItemAtURL:(NSURL *)url withContentsOfURL:(NSURL *)contentsURL options:(NSFileVersionAddingOptions)options error:(NSError * _Nullable *)outError {
    if([_hiddenjailbreak isURLRestricted:url] || [_hiddenjailbreak isURLRestricted:contentsURL]) {
        if(outError) {
            *outError = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

+ (NSArray<NSFileVersion *> *)unresolvedConflictVersionsOfItemAtURL:(NSURL *)url {
    if([_hiddenjailbreak isURLRestricted:url]) {
        return nil;
    }

    return %orig;
}

- (NSURL *)replaceItemAtURL:(NSURL *)url options:(NSFileVersionReplacingOptions)options error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:url]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

+ (BOOL)removeOtherVersionsOfItemAtURL:(NSURL *)url error:(NSError * _Nullable *)outError {
    if([_hiddenjailbreak isURLRestricted:url]) {
        if(outError) {
            *outError = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

+ (void)getNonlocalVersionsOfItemAtURL:(NSURL *)url completionHandler:(void (^)(NSArray<NSFileVersion *> *nonlocalFileVersions, NSError *error))completionHandler {
    if([_hiddenjailbreak isURLRestricted:url]) {
        if(completionHandler) {
            completionHandler(nil, _error_file_not_found);
        }

        return;
    }

    %orig;
}
%end
%end

%group hook_NSURL
%hook NSURL
- (BOOL)checkResourceIsReachableAndReturnError:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (NSURL *)fileReferenceURL {
    if([_hiddenjailbreak isURLRestricted:self]) {
        return nil;
    }

    return %orig;
}
%end
%end

%group hook_UIApplication
%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    if([_hiddenjailbreak isURLRestricted:url]) {
        return NO;
    }

    return %orig;
}
/*
- (BOOL)openURL:(NSURL *)url {
    if([_hiddenjailbreak isURLRestricted:url]) {
        return NO;
    }

    return %orig;
}

- (void)openURL:(NSURL *)url options:(NSDictionary<id, id> *)options completionHandler:(void (^)(BOOL success))completion {
    if([_hiddenjailbreak isURLRestricted:url]) {
        completion(NO);
        return;
    }

    %orig;
}
*/
%end
%end

%group hook_NSBundle
// #include "Hooks/Testing/NSBundle.xm"
%hook NSBundle
- (id)objectForInfoDictionaryKey:(NSString *)key {
    if([key isEqualToString:@"SignerIdentity"]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)bundleWithURL:(NSURL *)url {
    if([_hiddenjailbreak isURLRestricted:url]) {
        return nil;
    }
    
    return %orig;
}

+ (instancetype)bundleWithPath:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithURL:(NSURL *)url {
    if([_hiddenjailbreak isURLRestricted:url]) {
        return nil;
    }
    
    return %orig;
}

- (instancetype)initWithPath:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path]) {
        return nil;
    }

    return %orig;
}
%end
%end
/*
%group hook_CoreFoundation
%hookf(CFArrayRef, CFBundleGetAllBundles) {
    CFArrayRef cfbundles = %orig;
    CFIndex cfcount = CFArrayGetCount(cfbundles);

    NSMutableArray *filter = [NSMutableArray new];
    NSMutableArray *bundles = [NSMutableArray arrayWithArray:(__bridge NSArray *) cfbundles];

    // Filter return value.
    int i;
    for(i = 0; i < cfcount; i++) {
        CFBundleRef cfbundle = (CFBundleRef) CFArrayGetValueAtIndex(cfbundles, i);
        CFURLRef cfbundle_cfurl = CFBundleCopyExecutableURL(cfbundle);

        if(cfbundle_cfurl) {
            NSURL *bundle_url = (__bridge NSURL *) cfbundle_cfurl;

            if([_hiddenjailbreak isURLRestricted:bundle_url]) {
                continue;
            }
        }

        [filter addObject:bundles[i]];
    }

    return (__bridge CFArrayRef) [filter copy];
}

%hookf(CFReadStreamRef, CFReadStreamCreateWithFile, CFAllocatorRef alloc, CFURLRef fileURL) {
    NSURL *nsurl = (__bridge NSURL *)fileURL;

    if([nsurl isFileURL] && [_hiddenjailbreak isPathRestricted:[nsurl path] partial:NO]) {
        return NULL;
    }

    return %orig;
}

%hookf(CFWriteStreamRef, CFWriteStreamCreateWithFile, CFAllocatorRef alloc, CFURLRef fileURL) {
    NSURL *nsurl = (__bridge NSURL *)fileURL;

    if([nsurl isFileURL] && [_hiddenjailbreak isPathRestricted:[nsurl path] partial:NO]) {
        return NULL;
    }

    return %orig;
}

%hookf(CFURLRef, CFURLCreateFilePathURL, CFAllocatorRef allocator, CFURLRef url, CFErrorRef *error) {
    NSURL *nsurl = (__bridge NSURL *)url;

    if([nsurl isFileURL] && [_hiddenjailbreak isPathRestricted:[nsurl path] partial:NO]) {
        if(error) {
            *error = (__bridge CFErrorRef) _error_file_not_found;
        }
        
        return NULL;
    }

    return %orig;
}

%hookf(CFURLRef, CFURLCreateFileReferenceURL, CFAllocatorRef allocator, CFURLRef url, CFErrorRef *error) {
    NSURL *nsurl = (__bridge NSURL *)url;

    if([nsurl isFileURL] && [_hiddenjailbreak isPathRestricted:[nsurl path] partial:NO]) {
        if(error) {
            *error = (__bridge CFErrorRef) _error_file_not_found;
        }
        
        return NULL;
    }

    return %orig;
}
%end
*/
%group hook_NSUtilities
%hook NSProcessInfo
- (BOOL)isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion)version {
    // Override version checks that use this method.
    return YES;
}
%end

%hook UIImage
- (instancetype)initWithContentsOfFile:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

+ (UIImage *)imageWithContentsOfFile:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}
%end

%hook NSMutableArray
- (id)initWithContentsOfFile:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    if([_hiddenjailbreak isURLRestricted:url partial:NO]) {
        return nil;
    }

    return %orig;
}

+ (id)arrayWithContentsOfFile:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

+ (id)arrayWithContentsOfURL:(NSURL *)url {
    if([_hiddenjailbreak isURLRestricted:url partial:NO]) {
        return nil;
    }

    return %orig;
}
%end

%hook NSArray
- (id)initWithContentsOfFile:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

+ (id)arrayWithContentsOfFile:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

+ (id)arrayWithContentsOfURL:(NSURL *)url {
    if([_hiddenjailbreak isURLRestricted:url partial:NO]) {
        return nil;
    }

    return %orig;
}
%end

%hook NSMutableDictionary
- (id)initWithContentsOfFile:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    if([_hiddenjailbreak isURLRestricted:url partial:NO]) {
        return nil;
    }

    return %orig;
}
%end

%hook NSDictionary
- (id)initWithContentsOfFile:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url {
    if([_hiddenjailbreak isURLRestricted:url partial:NO]) {
        return nil;
    }

    return %orig;
}

- (id)initWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:url partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfFile:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:url partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

+ (id)dictionaryWithContentsOfURL:(NSURL *)url {
    if([_hiddenjailbreak isURLRestricted:url partial:NO]) {
        return nil;
    }

    return %orig;
}
%end

%hook NSString
- (instancetype)initWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path usedEncoding:(NSStringEncoding *)enc error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)stringWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)stringWithContentsOfFile:(NSString *)path usedEncoding:(NSStringEncoding *)enc error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

- (NSUInteger)completePathIntoString:(NSString * _Nullable *)outputName caseSensitive:(BOOL)flag matchesIntoArray:(NSArray<NSString *> * _Nullable *)outputArray filterTypes:(NSArray<NSString *> *)filterTypes {
    if([_hiddenjailbreak isPathRestricted:self]) {
        *outputName = nil;
        *outputArray = nil;

        return 0;
    }

    return %orig;
}
%end
%end

// Other Hooks
%group hook_private
%hookf(int, csops, pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    int ret = %orig;

    if(ops == CS_OPS_STATUS && (ret & CS_PLATFORM_BINARY) == CS_PLATFORM_BINARY && pid == getpid()) {
        // Ensure that the platform binary flag is not set.
        ret &= ~CS_PLATFORM_BINARY;
    }

    return ret;
}
%end

%group hook_debugging
%hookf(int, sysctl, int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if(namelen == 4
    && name[0] == CTL_KERN
    && name[1] == KERN_PROC
    && name[2] == KERN_PROC_ALL
    && name[3] == 0) {
        // Running process check.
        *oldlenp = 0;
        return 0;
    }

    int ret = %orig;

    if(ret == 0
    && name[0] == CTL_KERN
    && name[1] == KERN_PROC
    && name[2] == KERN_PROC_PID
    && name[3] == getpid()) {
        // Remove trace flag.
        if(oldp) {
            struct kinfo_proc *p = ((struct kinfo_proc *) oldp);

            if((p->kp_proc.p_flag & P_TRACED) == P_TRACED) {
                p->kp_proc.p_flag &= ~P_TRACED;
            }
        }
    }

    return ret;
}

%hookf(pid_t, getppid) {
    return 1;
}

/*
%hookf(int, "_ptrace", int request, pid_t pid, caddr_t addr, int data) {
    // PTRACE_DENY_ATTACH = 31
    if(request == 31) {
        return 0;
    }

    return %orig;
}
*/
%end

%group hook_dyld_image
%hookf(uint32_t, _dyld_image_count) {
    if(dyld_array_count > 0) {
        return dyld_array_count;
    }

    return %orig;
}

%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    if(dyld_array_count > 0) {
        // if(image_index == 0) {
        //     updateDyldArray();
        // }

        if(image_index >= dyld_array_count) {
            return NULL;
        }

        image_index = (uint32_t) [dyld_array[image_index] unsignedIntValue];
    }

    // Basic filter.
    const char *ret = %orig(image_index);

    if(ret) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:ret length:strlen(ret)];

        if([_hiddenjailbreak isImageRestricted:image_name]) {
            return "/.file";
        }
    }

    return ret;
}
/*
%hookf(const struct mach_header *, _dyld_get_image_header, uint32_t image_index) {
    static struct mach_header ret;

    if(dyld_array_count > 0) {
        if(image_index >= dyld_array_count) {
            return NULL;
        }

        // image_index = (uint32_t) [dyld_array[image_index] unsignedIntValue];
    }

    ret = *(%orig(image_index));

    return &ret;
}

%hookf(intptr_t, _dyld_get_image_vmaddr_slide, uint32_t image_index) {
    if(dyld_array_count > 0) {
        if(image_index >= dyld_array_count) {
            return 0;
        }

        // image_index = (uint32_t) [dyld_array[image_index] unsignedIntValue];
    }

    return %orig(image_index);
}
*/
%hookf(bool, dlopen_preflight, const char *path) {
    if(path) {
        NSString *image_name = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if([_hiddenjailbreak isImageRestricted:image_name]) {
            NSLog(@"blocked dlopen_preflight: %@", image_name);
            return false;
        }
    }

    return %orig;
}
%end

%group hook_dyld_dlsym
%hookf(void *, dlsym, void *handle, const char *symbol) {
    if(symbol) {
        NSString *sym = [NSString stringWithUTF8String:symbol];

        if([sym hasPrefix:@"MS"]
        || [sym hasPrefix:@"Sub"]
        || [sym hasPrefix:@"PS"]
        || [sym hasPrefix:@"rocketbootstrap"]
        || [sym hasPrefix:@"LM"]
        || [sym hasPrefix:@"substitute_"]
        || [sym hasPrefix:@"_logos"]) {
            NSLog(@"blocked dlsym lookup: %@", sym);
            return NULL;
        }
    }

    return %orig;
}
%end

%group hook_sandbox
%hook NSArray
- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)atomically {
    if([_hiddenjailbreak isURLRestricted:url partial:NO]) {
        return NO;
    }

    return %orig;
}
%end

%hook NSDictionary
- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:url partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)atomically {
    if([_hiddenjailbreak isURLRestricted:url partial:NO]) {
        return NO;
    }

    return %orig;
}
%end

%hook NSData
- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToFile:(NSString *)path options:(NSDataWritingOptions)writeOptionsMask error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)useAuxiliaryFile {
    if([_hiddenjailbreak isURLRestricted:url partial:NO]) {
        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url options:(NSDataWritingOptions)writeOptionsMask error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:url partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}
%end

%hook NSString
- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)useAuxiliaryFile encoding:(NSStringEncoding)enc error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:url partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}
%end

%hook NSFileManager
- (BOOL)createDirectoryAtURL:(NSURL *)url withIntermediateDirectories:(BOOL)createIntermediates attributes:(NSDictionary<NSFileAttributeKey, id> *)attributes error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:url partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)createDirectoryAtPath:(NSString *)path withIntermediateDirectories:(BOOL)createIntermediates attributes:(NSDictionary<NSFileAttributeKey, id> *)attributes error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)createFileAtPath:(NSString *)path contents:(NSData *)data attributes:(NSDictionary<NSFileAttributeKey, id> *)attr {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        return NO;
    }

    return %orig;
}

- (BOOL)removeItemAtURL:(NSURL *)URL error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:URL manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)removeItemAtPath:(NSString *)path error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:path manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}

- (BOOL)trashItemAtURL:(NSURL *)url resultingItemURL:(NSURL * _Nullable *)outResultingURL error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:url manager:self]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return NO;
    }

    return %orig;
}
%end

%hookf(int, creat, const char *pathname, mode_t mode) {
    if(pathname) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:pathname length:strlen(pathname)];

        if([_hiddenjailbreak isPathRestricted:path]) {
            errno = EACCES;
            return -1;
        }
    }

    return %orig;
}

%hookf(pid_t, vfork) {
    errno = ENOSYS;
    return -1;
}

%hookf(pid_t, fork) {
    errno = ENOSYS;
    return -1;
}

%hookf(FILE *, popen, const char *command, const char *type) {
    errno = ENOSYS;
    return NULL;
}

%hookf(int, setgid, gid_t gid) {
    // Block setgid for root.
    if(gid == 0) {
        errno = EPERM;
        return -1;
    }

    return %orig;
}

%hookf(int, setuid, uid_t uid) {
    // Block setuid for root.
    if(uid == 0) {
        errno = EPERM;
        return -1;
    }

    return %orig;
}

%hookf(int, setegid, gid_t gid) {
    // Block setegid for root.
    if(gid == 0) {
        errno = EPERM;
        return -1;
    }

    return %orig;
}

%hookf(int, seteuid, uid_t uid) {
    // Block seteuid for root.
    if(uid == 0) {
        errno = EPERM;
        return -1;
    }

    return %orig;
}

%hookf(uid_t, getuid) {
    // Return uid for mobile.
    return 501;
}

%hookf(gid_t, getgid) {
    // Return gid for mobile.
    return 501;
}

%hookf(uid_t, geteuid) {
    // Return uid for mobile.
    return 501;
}

%hookf(uid_t, getegid) {
    // Return gid for mobile.
    return 501;
}

%hookf(int, setreuid, uid_t ruid, uid_t euid) {
    // Block for root.
    if(ruid == 0 || euid == 0) {
        errno = EPERM;
        return -1;
    }

    return %orig;
}

%hookf(int, setregid, gid_t rgid, gid_t egid) {
    // Block for root.
    if(rgid == 0 || egid == 0) {
        errno = EPERM;
        return -1;
    }

    return %orig;
}
%end

%group hook_runtime
%hookf(const char * _Nonnull *, objc_copyImageNames, unsigned int *outCount) {
    const char * _Nonnull *ret = %orig;

    if(ret && outCount) {
        NSLog(@"copyImageNames: %d", *outCount);

        const char *exec_name = _dyld_get_image_name(0);
        unsigned int i;

        for(i = 0; i < *outCount; i++) {
            if(strcmp(ret[i], exec_name) == 0) {
                // Stop after app executable.
                *outCount = (i + 1);
                break;
            }
        }
    }

    return ret;
}

%hookf(const char * _Nonnull *, objc_copyClassNamesForImage, const char *image, unsigned int *outCount) {
    if(image) {
        NSLog(@"copyClassNamesForImage: %s", image);

        NSString *image_ns = [NSString stringWithUTF8String:image];

        if([_hiddenjailbreak isImageRestricted:image_ns]) {
            *outCount = 0;
            return NULL;
        }
    }

    return %orig;
}
%end

%group hook_libraries
%hook UIDevice
+ (BOOL)isJailbroken {
    return NO;
}

- (BOOL)isJailBreak {
    return NO;
}

- (BOOL)isJailBroken {
    return NO;
}
%end

// %hook SFAntiPiracy
// + (int)isJailbroken {
// 	// Probably should not hook with a hard coded value.
// 	// This value may be changed by developers using this library.
// 	// Best to defeat the checks rather than skip them.
// 	return 4783242;
// }
// %end

%hook JailbreakDetectionVC
- (BOOL)isJailbroken {
    return NO;
}
%end

%hook DTTJailbreakDetection
+ (BOOL)isJailbroken {
    return NO;
}
%end

%hook ANSMetadata
- (BOOL)computeIsJailbroken {
    return NO;
}

- (BOOL)isJailbroken {
    return NO;
}
%end

%hook AppsFlyerUtils
+ (BOOL)isJailBreakon {
    return NO;
}
%end

%hook GBDeviceInfo
- (BOOL)isJailbroken {
    return NO;
}
%end

%hook CMARAppRestrictionsDelegate
- (bool)isDeviceNonCompliant {
    return false;
}
%end

%hook ADYSecurityChecks
+ (bool)isDeviceJailbroken {
    return false;
}
%end

%hook UBReportMetadataDevice
- (void *)is_rooted {
    return NULL;
}
%end

%hook UtilitySystem
+ (bool)isJailbreak {
    return false;
}
%end

%hook GemaltoConfiguration
+ (bool)isJailbreak {
    return false;
}
%end

%hook CPWRDeviceInfo
- (bool)isJailbroken {
    return false;
}
%end

%hook CPWRSessionInfo
- (bool)isJailbroken {
    return false;
}
%end

%hook KSSystemInfo
+ (bool)isJailbroken {
    return false;
}
%end

%hook EMDSKPPConfiguration
- (bool)jailBroken {
    return false;
}
%end

%hook EnrollParameters
- (void *)jailbroken {
    return NULL;
}
%end

%hook EMDskppConfigurationBuilder
- (bool)jailbreakStatus {
    return false;
}
%end

%hook FCRSystemMetadata
- (bool)isJailbroken {
    return false;
}
%end

%hook v_VDMap
- (bool)isJailBrokenDetectedByVOS {
    return false;
}

- (bool)isDFPHookedDetecedByVOS {
    return false;
}

- (bool)isCodeInjectionDetectedByVOS {
    return false;
}

- (bool)isDebuggerCheckDetectedByVOS {
    return false;
}

- (bool)isAppSignerCheckDetectedByVOS {
    return false;
}

- (bool)v_checkAModified {
    return false;
}
%end

%hook SDMUtils
- (BOOL)isJailBroken {
    return NO;
}
%end

%hook OneSignalJailbreakDetection
+ (BOOL)isJailbroken {
    return NO;
}
%end

%hook DigiPassHandler
- (BOOL)rootedDeviceTestResult {
    return NO;
}
%end

%hook AWMyDeviceGeneralInfo
- (bool)isCompliant {
    return true;
}
%end
%end

%group hook_experimental
%hook NSData
- (id)initWithContentsOfMappedFile:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

+ (id)dataWithContentsOfMappedFile:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url {
    if([_hiddenjailbreak isURLRestricted:url partial:NO]) {
        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:url partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }
        
        return nil;
    }

    return %orig;
}

+ (instancetype)dataWithContentsOfFile:(NSString *)path {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url {
    if([_hiddenjailbreak isURLRestricted:url partial:NO]) {
        return nil;
    }

    return %orig;
}

+ (instancetype)dataWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isPathRestricted:path partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError * _Nullable *)error {
    if([_hiddenjailbreak isURLRestricted:url partial:NO]) {
        if(error) {
            *error = _error_file_not_found;
        }

        return nil;
    }

    return %orig;
}
%end

%hookf(int32_t, NSVersionOfRunTimeLibrary, const char *libraryName) {
    if(libraryName) {
        NSString *name = [NSString stringWithUTF8String:libraryName];

        if([_hiddenjailbreak isImageRestricted:name]) {
            return -1;
        }
    }
    
    return %orig;
}

%hookf(int32_t, NSVersionOfLinkTimeLibrary, const char *libraryName) {
    if(libraryName) {
        NSString *name = [NSString stringWithUTF8String:libraryName];

        if([_hiddenjailbreak isImageRestricted:name]) {
            return -1;
        }
    }
    
    return %orig;
}
%end

void init_path_map(HiddenJailbreak *HiddenJailbreak) {
    // Restrict / by whitelisting
    [HiddenJailbreak addPath:@"/" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/.file" restricted:NO];
    [HiddenJailbreak addPath:@"/.ba" restricted:NO];
    [HiddenJailbreak addPath:@"/.mb" restricted:NO];
    [HiddenJailbreak addPath:@"/.HFS" restricted:NO];
    [HiddenJailbreak addPath:@"/.Trashes" restricted:NO];
    // [HiddenJailbreak addPath:@"/AppleInternal" restricted:NO];
    [HiddenJailbreak addPath:@"/cores" restricted:NO];
    [HiddenJailbreak addPath:@"/Developer" restricted:NO];
    [HiddenJailbreak addPath:@"/lib" restricted:NO];
    [HiddenJailbreak addPath:@"/mnt" restricted:NO];

    // Restrict /bin by whitelisting
    [HiddenJailbreak addPath:@"/bin" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/bin/df" restricted:NO];
    [HiddenJailbreak addPath:@"/bin/ps" restricted:NO];

    // Restrict /sbin by whitelisting
    [HiddenJailbreak addPath:@"/sbin" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/sbin/fsck" restricted:NO];
    [HiddenJailbreak addPath:@"/sbin/launchd" restricted:NO];
    [HiddenJailbreak addPath:@"/sbin/mount" restricted:NO];
    [HiddenJailbreak addPath:@"/sbin/pfctl" restricted:NO];

    // Restrict /Applications by whitelisting
    [HiddenJailbreak addPath:@"/Applications" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/Applications/AXUIViewService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/AccountAuthenticationDialog.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/ActivityMessagesApp.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/AdPlatformsDiagnostics.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/AppStore.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/AskPermissionUI.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/BusinessExtensionsWrapper.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/CTCarrierSpaceAuth.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/Camera.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/CheckerBoard.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/CompassCalibrationViewService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/ContinuityCamera.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/CoreAuthUI.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/DDActionsService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/DNDBuddy.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/DataActivation.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/DemoApp.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/Diagnostics.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/DiagnosticsService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/FTMInternal-4.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/Family.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/Feedback Assistant iOS.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/FieldTest.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/FindMyiPhone.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/FunCameraShapes.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/FunCameraText.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/GameCenterUIService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/HashtagImages.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/Health.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/HealthPrivacyService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/HomeUIService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/InCallService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/Magnifier.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/MailCompositionService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/MessagesViewService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/MobilePhone.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/MobileSMS.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/MobileSafari.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/MobileSlideShow.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/MobileTimer.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/MusicUIService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/Passbook.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/PassbookUIService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/PhotosViewService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/PreBoard.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/Preferences.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/Print Center.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/SIMSetupUIService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/SLGoogleAuth.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/SLYahooAuth.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/SafariViewService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/ScreenSharingViewService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/ScreenshotServicesService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/Setup.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/SharedWebCredentialViewService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/SharingViewService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/SiriViewService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/SoftwareUpdateUIService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/StoreDemoViewService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/StoreKitUIService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/TrustMe.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/Utilities" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/VideoSubscriberAccountViewService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/WLAccessService.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/Web.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/WebApp1.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/WebContentAnalysisUI.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/WebSheet.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/iAdOptOut.app" restricted:NO];
    [HiddenJailbreak addPath:@"/Applications/iCloud.app" restricted:NO];

    // Restrict /dev
    [HiddenJailbreak addPath:@"/dev" restricted:NO];
    [HiddenJailbreak addPath:@"/dev/dlci." restricted:YES];
    [HiddenJailbreak addPath:@"/dev/vn0" restricted:YES];
    [HiddenJailbreak addPath:@"/dev/vn1" restricted:YES];
    [HiddenJailbreak addPath:@"/dev/kmem" restricted:YES];
    [HiddenJailbreak addPath:@"/dev/mem" restricted:YES];

    // Restrict /private by whitelisting
    [HiddenJailbreak addPath:@"/private" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/private/etc" restricted:NO];
    [HiddenJailbreak addPath:@"/private/system_data" restricted:NO];
    [HiddenJailbreak addPath:@"/private/var" restricted:NO];
    [HiddenJailbreak addPath:@"/private/xarts" restricted:NO];

    // Restrict /etc by whitelisting
    [HiddenJailbreak addPath:@"/etc" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/etc/asl" restricted:NO];
    [HiddenJailbreak addPath:@"/etc/asl.conf" restricted:NO];
    [HiddenJailbreak addPath:@"/etc/fstab" restricted:NO];
    [HiddenJailbreak addPath:@"/etc/group" restricted:NO];
    [HiddenJailbreak addPath:@"/etc/hosts" restricted:NO];
    [HiddenJailbreak addPath:@"/etc/hosts.equiv" restricted:NO];
    [HiddenJailbreak addPath:@"/etc/master.passwd" restricted:NO];
    [HiddenJailbreak addPath:@"/etc/networks" restricted:NO];
    [HiddenJailbreak addPath:@"/etc/notify.conf" restricted:NO];
    [HiddenJailbreak addPath:@"/etc/passwd" restricted:NO];
    [HiddenJailbreak addPath:@"/etc/ppp" restricted:NO];
    [HiddenJailbreak addPath:@"/etc/protocols" restricted:NO];
    [HiddenJailbreak addPath:@"/etc/racoon" restricted:NO];
    [HiddenJailbreak addPath:@"/etc/services" restricted:NO];
    [HiddenJailbreak addPath:@"/etc/ttys" restricted:NO];
    
    // Restrict /Library by whitelisting
    [HiddenJailbreak addPath:@"/Library" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/Library/Application Support" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/Library/Application Support/AggregateDictionary" restricted:NO];
    [HiddenJailbreak addPath:@"/Library/Application Support/BTServer" restricted:NO];
    [HiddenJailbreak addPath:@"/Library/Audio" restricted:NO];
    [HiddenJailbreak addPath:@"/Library/Caches" restricted:NO];
    [HiddenJailbreak addPath:@"/Library/Caches/cy-" restricted:YES];
    [HiddenJailbreak addPath:@"/Library/Filesystems" restricted:NO];
    [HiddenJailbreak addPath:@"/Library/Internet Plug-Ins" restricted:NO];
    [HiddenJailbreak addPath:@"/Library/Keychains" restricted:NO];
    [HiddenJailbreak addPath:@"/Library/LaunchAgents" restricted:NO];
    [HiddenJailbreak addPath:@"/Library/LaunchDaemons" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/Library/Logs" restricted:NO];
    [HiddenJailbreak addPath:@"/Library/Managed Preferences" restricted:NO];
    [HiddenJailbreak addPath:@"/Library/MobileDevice" restricted:NO];
    [HiddenJailbreak addPath:@"/Library/MusicUISupport" restricted:NO];
    [HiddenJailbreak addPath:@"/Library/Preferences" restricted:NO];
    [HiddenJailbreak addPath:@"/Library/Printers" restricted:NO];
    [HiddenJailbreak addPath:@"/Library/Ringtones" restricted:NO];
    [HiddenJailbreak addPath:@"/Library/Updates" restricted:NO];
    [HiddenJailbreak addPath:@"/Library/Wallpaper" restricted:NO];
    
    // Restrict /tmp
    [HiddenJailbreak addPath:@"/tmp" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/tmp/com.apple" restricted:NO];
    [HiddenJailbreak addPath:@"/tmp/substrate" restricted:YES];
    [HiddenJailbreak addPath:@"/tmp/Substrate" restricted:YES];
    [HiddenJailbreak addPath:@"/tmp/cydia.log" restricted:YES];
    [HiddenJailbreak addPath:@"/tmp/syslog" restricted:YES];
    [HiddenJailbreak addPath:@"/tmp/slide.txt" restricted:YES];
    [HiddenJailbreak addPath:@"/tmp/amfidebilitate.out" restricted:YES];
    [HiddenJailbreak addPath:@"/tmp/org.coolstar" restricted:YES];
    [HiddenJailbreak addPath:@"/tmp/amfid_payload.alive" restricted:YES];
    [HiddenJailbreak addPath:@"/tmp/jailbreakd.pid" restricted:YES];

    // Restrict /var by whitelisting
    [HiddenJailbreak addPath:@"/var" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/var/.DocumentRevisions" restricted:NO];
    [HiddenJailbreak addPath:@"/var/.fseventsd" restricted:NO];
    [HiddenJailbreak addPath:@"/var/.overprovisioning_file" restricted:NO];
    [HiddenJailbreak addPath:@"/var/audit" restricted:NO];
    [HiddenJailbreak addPath:@"/var/backups" restricted:NO];
    [HiddenJailbreak addPath:@"/var/buddy" restricted:NO];
    [HiddenJailbreak addPath:@"/var/containers" restricted:NO];
    [HiddenJailbreak addPath:@"/var/containers/Bundle" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/var/containers/Bundle/Application" restricted:NO];
    [HiddenJailbreak addPath:@"/var/containers/Bundle/Framework" restricted:NO];
    [HiddenJailbreak addPath:@"/var/containers/Bundle/PluginKitPlugin" restricted:NO];
    [HiddenJailbreak addPath:@"/var/containers/Bundle/VPNPlugin" restricted:NO];
    [HiddenJailbreak addPath:@"/var/cores" restricted:NO];
    [HiddenJailbreak addPath:@"/var/db" restricted:NO];
    [HiddenJailbreak addPath:@"/var/db/stash" restricted:YES];
    [HiddenJailbreak addPath:@"/var/ea" restricted:NO];
    [HiddenJailbreak addPath:@"/var/empty" restricted:NO];
    [HiddenJailbreak addPath:@"/var/folders" restricted:NO];
    [HiddenJailbreak addPath:@"/var/hardware" restricted:NO];
    [HiddenJailbreak addPath:@"/var/installd" restricted:NO];
    [HiddenJailbreak addPath:@"/var/internal" restricted:NO];
    [HiddenJailbreak addPath:@"/var/keybags" restricted:NO];
    [HiddenJailbreak addPath:@"/var/Keychains" restricted:NO];
    [HiddenJailbreak addPath:@"/var/lib" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/var/local" restricted:NO];
    [HiddenJailbreak addPath:@"/var/lock" restricted:NO];
    [HiddenJailbreak addPath:@"/var/log" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/var/log/asl" restricted:NO];
    [HiddenJailbreak addPath:@"/var/log/com.apple.xpc.launchd" restricted:NO];
    [HiddenJailbreak addPath:@"/var/log/corecaptured.log" restricted:NO];
    [HiddenJailbreak addPath:@"/var/log/ppp" restricted:NO];
    [HiddenJailbreak addPath:@"/var/log/ppp.log" restricted:NO];
    [HiddenJailbreak addPath:@"/var/log/racoon.log" restricted:NO];
    [HiddenJailbreak addPath:@"/var/log/sa" restricted:NO];
    [HiddenJailbreak addPath:@"/var/logs" restricted:NO];
    [HiddenJailbreak addPath:@"/var/Managed Preferences" restricted:NO];
    [HiddenJailbreak addPath:@"/var/MobileAsset" restricted:NO];
    [HiddenJailbreak addPath:@"/var/MobileDevice" restricted:NO];
    [HiddenJailbreak addPath:@"/var/MobileSoftwareUpdate" restricted:NO];
    [HiddenJailbreak addPath:@"/var/msgs" restricted:NO];
    [HiddenJailbreak addPath:@"/var/networkd" restricted:NO];
    [HiddenJailbreak addPath:@"/var/preferences" restricted:NO];
    [HiddenJailbreak addPath:@"/var/root" restricted:NO];
    [HiddenJailbreak addPath:@"/var/run" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/var/run/lockdown" restricted:NO];
    [HiddenJailbreak addPath:@"/var/run/lockdown.sock" restricted:NO];
    [HiddenJailbreak addPath:@"/var/run/lockdown_first_run" restricted:NO];
    [HiddenJailbreak addPath:@"/var/run/mDNSResponder" restricted:NO];
    [HiddenJailbreak addPath:@"/var/run/printd" restricted:NO];
    [HiddenJailbreak addPath:@"/var/run/syslog" restricted:NO];
    [HiddenJailbreak addPath:@"/var/run/syslog.pid" restricted:NO];
    [HiddenJailbreak addPath:@"/var/run/utmpx" restricted:NO];
    [HiddenJailbreak addPath:@"/var/run/vpncontrol.sock" restricted:NO];
    [HiddenJailbreak addPath:@"/var/run/asl_input" restricted:NO];
    [HiddenJailbreak addPath:@"/var/run/configd.pid" restricted:NO];
    [HiddenJailbreak addPath:@"/var/run/lockbot" restricted:NO];
    [HiddenJailbreak addPath:@"/var/run/pppconfd" restricted:NO];
    [HiddenJailbreak addPath:@"/var/run/fudinit" restricted:NO];
    [HiddenJailbreak addPath:@"/var/spool" restricted:NO];
    [HiddenJailbreak addPath:@"/var/staged_system_apps" restricted:NO];
    [HiddenJailbreak addPath:@"/var/tmp" restricted:NO];
    [HiddenJailbreak addPath:@"/var/vm" restricted:NO];
    [HiddenJailbreak addPath:@"/var/wireless" restricted:NO];
    
    // Restrict /var/mobile by whitelisting
    [HiddenJailbreak addPath:@"/var/mobile" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Applications" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Containers" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Containers/Data" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Containers/Data/Application" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Containers/Data/InternalDaemon" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Containers/Data/PluginKitPlugin" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Containers/Data/TempDir" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Containers/Data/VPNPlugin" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Containers/Data/XPCService" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Containers/Shared" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Containers/Shared/AppGroup" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Documents" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Downloads" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/com.apple" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/.com.apple" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/AdMob" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/AccountMigrationInProgress" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/ACMigrationLock" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/BTAvrcp" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/cache" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/Checkpoint.plist" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/ckkeyrolld" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/CloudKit" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/DateFormats.plist" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/FamilyCircle" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/GameKit" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/GeoServices" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/AccountMigrationInProgress" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/MappedImageCache" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/OTACrashCopier" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/PassKit" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/rtcreportingd" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/sharedCaches" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/Snapshots" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/Snapshots/com.apple" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/TelephonyUI" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Caches/Weather" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/ControlCenter" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/ControlCenter/ModuleConfiguration.plist" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Cydia" restricted:YES];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Logs/Cydia" restricted:YES];
    [HiddenJailbreak addPath:@"/var/mobile/Library/SBSettings" restricted:YES];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Sileo" restricted:YES];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Preferences" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Preferences/com.apple." restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Preferences/.GlobalPreferences.plist" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Preferences/ckkeyrolld.plist" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Preferences/nfcd.plist" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Preferences/UITextInputContextIdentifiers.plist" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Library/Preferences/Wallpaper.png" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/Media" restricted:NO];
    [HiddenJailbreak addPath:@"/var/mobile/MobileSoftwareUpdate" restricted:NO];

    // Restrict /usr by whitelisting
    [HiddenJailbreak addPath:@"/usr" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/usr/bin" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/usr/bin/DumpBasebandCrash" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/bin/PerfPowerServicesExtended" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/bin/abmlite" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/bin/brctl" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/bin/footprint" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/bin/hidutil" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/bin/hpmdiagnose" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/bin/kbdebug" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/bin/powerlogHelperd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/bin/sysdiagnose" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/bin/tailspin" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/bin/taskinfo" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/bin/vm_stat" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/bin/zprint" restricted:NO];

    if([HiddenJailbreak useTweakCompatibilityMode] && extra_compat) {
        [HiddenJailbreak addPath:@"/usr/lib" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libsubstrate" restricted:YES];
        [HiddenJailbreak addPath:@"/usr/lib/libsubstitute" restricted:YES];
        [HiddenJailbreak addPath:@"/usr/lib/libSubstitrate" restricted:YES];
        [HiddenJailbreak addPath:@"/usr/lib/TweakInject" restricted:YES];
        [HiddenJailbreak addPath:@"/usr/lib/substrate" restricted:YES];
        [HiddenJailbreak addPath:@"/usr/lib/tweaks" restricted:YES];
        [HiddenJailbreak addPath:@"/usr/lib/apt" restricted:YES];
        [HiddenJailbreak addPath:@"/usr/lib/bash" restricted:YES];
        [HiddenJailbreak addPath:@"/usr/lib/cycript" restricted:YES];
        [HiddenJailbreak addPath:@"/usr/lib/libmis.dylib" restricted:YES];
    } else {
        [HiddenJailbreak addPath:@"/usr/lib" restricted:YES hidden:NO];
        [HiddenJailbreak addPath:@"/usr/lib/FDRSealingMap.plist" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/bbmasks" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/dyld" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libCRFSuite" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libDHCPServer" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libMatch" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libSystem" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libarchive" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libbsm" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libbz2" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libc++" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libc" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libcharset" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libcurses" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libdbm" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libdl" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libeasyperf" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libedit" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libexslt" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libextension" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libform" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libiconv" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libicucore" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libinfo" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libipsec" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/liblzma" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libm" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libmecab" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libncurses" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libobjc" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libpcap" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libpmsample" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libpoll" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libproc" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libpthread" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libresolv" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/librpcsvc" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libsandbox" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libsqlite3" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libstdc++" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libtidy" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libutil" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libxml2" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libxslt" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libz" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libperfcheck" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/libedit" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/log" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/system" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/updaters" restricted:NO];
        [HiddenJailbreak addPath:@"/usr/lib/xpc" restricted:NO];
    }
    
    [HiddenJailbreak addPath:@"/usr/libexec" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/BackupAgent" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/BackupAgent2" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/CrashHousekeeping" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/DataDetectorsSourceAccess" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/FSTaskScheduler" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/FinishRestoreFromBackup" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/IOAccelMemoryInfoCollector" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/IOMFB_bics_daemon" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/Library" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/MobileGestaltHelper" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/MobileStorageMounter" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/NANDTaskScheduler" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/OTATaskingAgent" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/PowerUIAgent" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/PreboardService" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/ProxiedCrashCopier" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/PurpleReverseProxy" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/ReportMemoryException" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/SafariCloudHistoryPushAgent" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/SidecarRelay" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/SyncAgent" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/UserEventAgent" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/addressbooksyncd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/adid" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/adprivacyd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/adservicesd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/afcd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/airtunesd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/amfid" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/asd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/assertiond" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/atc" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/atwakeup" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/backboardd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/biometrickitd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/bootpd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/bulletindistributord" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/captiveagent" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/cc_fips_test" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/checkpointd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/cloudpaird" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/com.apple.automation.defaultslockdownserviced" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/companion_proxy" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/configd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/corecaptured" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/coreduetd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/crash_mover" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/dasd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/demod" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/demod_helper" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/dhcpd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/diagnosticd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/diagnosticextensionsd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/dmd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/dprivacyd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/dtrace" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/duetexpertd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/eventkitsyncd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/fdrhelper" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/findmydeviced" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/finish_demo_restore" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/fmfd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/fmflocatord" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/fseventsd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/ftp-proxy" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/gamecontrollerd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/gamed" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/gpsd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/hangreporter" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/hangtracerd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/heartbeatd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/hostapd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/idamd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/init_data_protection -> seputil" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/installd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/ioupsd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/keybagd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/languageassetd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/locationd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/lockdownd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/logd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/lsd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/lskdd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/lskdmsed" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/magicswitchd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/mc_mobile_tunnel" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/microstackshot" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/misagent" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/misd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/mmaintenanced" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/mobile_assertion_agent" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/mobile_diagnostics_relay" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/mobile_house_arrest" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/mobile_installation_proxy" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/mobile_obliterator" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/mobile_storage_proxy" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/mobileactivationd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/mobileassetd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/mobilewatchdog" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/mtmergeprops" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/nanomediaremotelinkagent" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/nanoregistryd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/nanoregistrylaunchd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/neagent" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/nehelper" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/nesessionmanager" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/networkserviceproxy" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/nfcd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/nfrestore_service" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/nlcd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/notification_proxy" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/nptocompaniond" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/nsurlsessiond" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/nsurlstoraged" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/online-auth-agent" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/oscard" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/pcapd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/pcsstatus" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/pfd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/pipelined" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/pkd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/pkreporter" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/ptpd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/rapportd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/replayd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/resourcegrabberd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/rolld" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/routined" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/rtbuddyd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/rtcreportingd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/safarifetcherd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/screenshotsyncd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/security-sysdiagnose" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/securityd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/securityuploadd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/seld" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/seputil" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/sharingd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/signpost_reporter" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/silhouette" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/siriknowledged" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/smcDiagnose" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/splashboardd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/springboardservicesrelay" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/streaming_zip_conduit" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/swcd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/symptomsd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/symptomsd-helper" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/sysdiagnose_helper" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/sysstatuscheck" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/tailspind" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/timed" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/tipsd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/topicsmap.db" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/transitd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/trustd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/tursd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/tzd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/tzinit" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/tzlinkd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/videosubscriptionsd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/wapic" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/wcd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/webbookmarksd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/webinspectord" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/wifiFirmwareLoader" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/wifivelocityd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/xpcproxy" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/libexec/xpcroleaccountd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/local" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/usr/local/bin" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/usr/local/lib" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/usr/local/standalone" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/BTAvrcp" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/BTLEServer" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/BTMap" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/BTPbap" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/BlueTool" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/WiFiNetworkStoreModel.momd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/WirelessRadioManagerd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/absd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/addNetworkInterface" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/applecamerad" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/aslmanager" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/bluetoothd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/cfprefsd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/ckksctl" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/distnoted" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/fairplayd.H2" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/filecoordinationd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/ioreg" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/ipconfig" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/mDNSResponder" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/mDNSResponderHelper" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/mediaserverd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/notifyd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/nvram" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/pppd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/racoon" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/rtadvd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/scutil" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/spindump" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/syslogd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/wifid" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/sbin/wirelessproxd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/share" restricted:YES hidden:NO];
    [HiddenJailbreak addPath:@"/usr/share/com.apple.languageassetd" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/share/CSI" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/share/firmware" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/share/icu" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/share/langid" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/share/locale" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/share/mecabra" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/share/misc" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/share/progressui" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/share/tokenizer" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/share/zoneinfo" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/share/zoneinfo.default" restricted:NO];
    [HiddenJailbreak addPath:@"/usr/standalone" restricted:NO];

    // Restrict /System
    [HiddenJailbreak addPath:@"/System" restricted:NO];
    [HiddenJailbreak addPath:@"/System/Library/PreferenceBundles/AppList.bundle" restricted:YES];
}

// Manual hooks
#include <dirent.h>

static int (*orig_open)(const char *path, int oflag, ...);
static int hook_open(const char *path, int oflag, ...) {
    int result = 0;

    if(path) {
        NSString *pathname = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if([_hiddenjailbreak isPathRestricted:pathname]) {
            errno = ((oflag & O_CREAT) == O_CREAT) ? EACCES : ENOENT;
            return -1;
        }
    }
    
    if((oflag & O_CREAT) == O_CREAT) {
        mode_t mode;
        va_list args;
        
        va_start(args, oflag);
        mode = (mode_t) va_arg(args, int);
        va_end(args);

        result = orig_open(path, oflag, mode);
    } else {
        result = orig_open(path, oflag);
    }

    return result;
}

static int (*orig_openat)(int fd, const char *path, int oflag, ...);
static int hook_openat(int fd, const char *path, int oflag, ...) {
    int result = 0;

    if(path) {
        NSString *nspath = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

        if(![nspath isAbsolutePath]) {
            // Get path of dirfd.
            char dirfdpath[PATH_MAX];
        
            if(fcntl(fd, F_GETPATH, dirfdpath) != -1) {
                NSString *dirfd_path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:dirfdpath length:strlen(dirfdpath)];
                nspath = [dirfd_path stringByAppendingPathComponent:nspath];
            }
        }
        
        if([_hiddenjailbreak isPathRestricted:nspath]) {
            errno = ((oflag & O_CREAT) == O_CREAT) ? EACCES : ENOENT;
            return -1;
        }
    }
    
    if((oflag & O_CREAT) == O_CREAT) {
        mode_t mode;
        va_list args;
        
        va_start(args, oflag);
        mode = (mode_t) va_arg(args, int);
        va_end(args);

        result = orig_openat(fd, path, oflag, mode);
    } else {
        result = orig_openat(fd, path, oflag);
    }

    return result;
}

static DIR *(*orig_opendir)(const char *filename);
static DIR *hook_opendir(const char *filename) {
    if(filename) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:filename length:strlen(filename)];

        if([_hiddenjailbreak isPathRestricted:path]) {
            errno = ENOENT;
            return NULL;
        }
    }

    return orig_opendir(filename);
}

static struct dirent *(*orig_readdir)(DIR *dirp);
static struct dirent *hook_readdir(DIR *dirp) {
    struct dirent *ret = NULL;
    NSString *path = nil;

    // Get path of dirfd.
    NSString *dirfd_path = nil;
    int fd = dirfd(dirp);
    char dirfdpath[PATH_MAX];

    if(fcntl(fd, F_GETPATH, dirfdpath) != -1) {
        dirfd_path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:dirfdpath length:strlen(dirfdpath)];
    } else {
        return orig_readdir(dirp);
    }

    // Filter returned results, skipping over restricted paths.
    do {
        ret = orig_readdir(dirp);

        if(ret) {
            path = [dirfd_path stringByAppendingPathComponent:[NSString stringWithUTF8String:ret->d_name]];
        } else {
            break;
        }
    } while([_hiddenjailbreak isPathRestricted:path]);

    return ret;
}

static int (*orig_dladdr)(const void *addr, Dl_info *info);
static int hook_dladdr(const void *addr, Dl_info *info) {
    int ret = orig_dladdr(addr, info);

    if(!passthrough && ret) {
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:info->dli_fname length:strlen(info->dli_fname)];

        if([_hiddenjailbreak isImageRestricted:path]) {
            return 0;
        }
    }

    return ret;
}

static ssize_t (*orig_readlink)(const char *path, char *buf, size_t bufsiz);
static ssize_t hook_readlink(const char *path, char *buf, size_t bufsiz) {
    if(!path || !buf) {
        return orig_readlink(path, buf, bufsiz);
    }

    NSString *nspath = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

    if([_hiddenjailbreak isPathRestricted:nspath]) {
        errno = ENOENT;
        return -1;
    }

    ssize_t ret = orig_readlink(path, buf, bufsiz);

    if(ret != -1) {
        buf[ret] = '\0';

        // Track this symlink in HiddenJailbreak
        [_hiddenjailbreak addLinkFromPath:nspath toPath:[[NSFileManager defaultManager] stringWithFileSystemRepresentation:buf length:strlen(buf)]];
    }

    return ret;
}

static ssize_t (*orig_readlinkat)(int fd, const char *path, char *buf, size_t bufsiz);
static ssize_t hook_readlinkat(int fd, const char *path, char *buf, size_t bufsiz) {
    if(!path || !buf) {
        return orig_readlinkat(fd, path, buf, bufsiz);
    }

    NSString *nspath = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];

    if(![nspath isAbsolutePath]) {
        // Get path of dirfd.
        char dirfdpath[PATH_MAX];
    
        if(fcntl(fd, F_GETPATH, dirfdpath) != -1) {
            NSString *dirfd_path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:dirfdpath length:strlen(dirfdpath)];
            nspath = [dirfd_path stringByAppendingPathComponent:nspath];
        }
    }

    if([_hiddenjailbreak isPathRestricted:nspath]) {
        errno = ENOENT;
        return -1;
    }

    ssize_t ret = orig_readlinkat(fd, path, buf, bufsiz);

    if(ret != -1) {
        buf[ret] = '\0';

        // Track this symlink in HiddenJailbreak
        [_hiddenjailbreak addLinkFromPath:nspath toPath:[[NSFileManager defaultManager] stringWithFileSystemRepresentation:buf length:strlen(buf)]];
    }

    return ret;
}

%group hook_springboard
%hook SpringBoard
- (void)applicationDidFinishLaunching:(UIApplication *)application {
    %orig;

    HBPreferences *prefs = [HBPreferences preferencesForIdentifier:BLACKLIST_PATH];

    NSArray *file_map = [HiddenJailbreak generateFileMap];
    NSArray *url_set = [HiddenJailbreak generateSchemeArray];

    [prefs setObject:file_map forKey:@"files"];
    [prefs setObject:url_set forKey:@"schemes"];
}
%end
%end

%ctor {
    NSString *processName = [[NSProcessInfo processInfo] processName];

    if([processName isEqualToString:@"SpringBoard"]) {
        HBPreferences *prefs = [HBPreferences preferencesForIdentifier:PREFS_TWEAK_ID];

        if(prefs && [prefs boolForKey:@"auto_file_map_generation_enabled"]) {
            %init(hook_springboard);
        }

        return;
    }

    NSBundle *bundle = [NSBundle mainBundle];

    if(bundle != nil) {
        NSString *executablePath = [bundle executablePath];
        NSString *bundleIdentifier = [bundle bundleIdentifier];

        // User (Sandboxed) Applications
        if([executablePath hasPrefix:@"/var/containers/Bundle/Application"]
        || [executablePath hasPrefix:@"/private/var/containers/Bundle/Application"]
        || [executablePath hasPrefix:@"/var/mobile/Containers/Bundle/Application"]
        || [executablePath hasPrefix:@"/private/var/mobile/Containers/Bundle/Application"]) {
            NSLog(@"bundleIdentifier: %@", bundleIdentifier);

            HBPreferences *prefs = [HBPreferences preferencesForIdentifier:PREFS_TWEAK_ID];

            [prefs registerDefaults:@{
                @"enabled" : @YES,
                @"mode" : @"whitelist",
                @"bypass_checks" : @YES,
                @"exclude_system_apps" : @YES,
                @"dyld_hooks_enabled" : @YES,
                @"extra_compat_enabled" : @YES
            }];

            extra_compat = [prefs boolForKey:@"extra_compat_enabled"];
            
            // Check if HiddenJailbreak is enabled
            if(![prefs boolForKey:@"enabled"]) {
                // HiddenJailbreak disabled in preferences
                return;
            }

            // Check if safe bundleIdentifier
            if([prefs boolForKey:@"exclude_system_apps"]) {
                // Disable HiddenJailbreak for Apple and jailbreak apps
                NSArray *excluded_bundleids = @[
                    @"com.apple", // Apple apps
                    @"is.workflow.my.app", // Shortcuts
                    @"science.xnu.undecimus", // unc0ver
                    @"com.electrateam.chimera", // Chimera
                    @"org.coolstar.electra" // Electra
                ];

                for(NSString *bundle_id in excluded_bundleids) {
                    if([bundleIdentifier hasPrefix:bundle_id]) {
                        return;
                    }
                }
            }

            HBPreferences *prefs_apps = [HBPreferences preferencesForIdentifier:APPS_PATH];

            // Check if excluded bundleIdentifier
            NSString *mode = [prefs objectForKey:@"mode"];

            if([mode isEqualToString:@"whitelist"]) {
                // Whitelist - disable HiddenJailbreak if not enabled for this bundleIdentifier
                if(![prefs_apps boolForKey:bundleIdentifier]) {
                    return;
                }
            } else {
                // Blacklist - disable HiddenJailbreak if enabled for this bundleIdentifier
                if([prefs_apps boolForKey:bundleIdentifier]) {
                    return;
                }
            }

            HBPreferences *prefs_blacklist = [HBPreferences preferencesForIdentifier:BLACKLIST_PATH];
            HBPreferences *prefs_tweakcompat = [HBPreferences preferencesForIdentifier:TWEAKCOMPAT_PATH];
            HBPreferences *prefs_lockdown = [HBPreferences preferencesForIdentifier:LOCKDOWN_PATH];
            HBPreferences *prefs_dlfcn = [HBPreferences preferencesForIdentifier:DLFCN_PATH];

            // Initialize HiddenJailbreak
            _hiddenjailbreak = [HiddenJailbreak new];

            if(!_hiddenjailbreak) {
                NSLog(@"failed to initialize HiddenJailbreak");
                return;
            }

            // Compatibility mode
            [_hiddenjailbreak setUseTweakCompatibilityMode:[prefs_tweakcompat boolForKey:bundleIdentifier] ? NO : YES];

            // Disable inject compatibility if we are using Substitute.
            NSFileManager *fm = [NSFileManager defaultManager];
            BOOL isSubstitute = ([fm fileExistsAtPath:@"/usr/lib/libsubstitute.dylib"] && ![fm fileExistsAtPath:@"/usr/lib/substrate"]);

            if(isSubstitute) {
                [_hiddenjailbreak setUseInjectCompatibilityMode:NO];
                NSLog(@"detected Substitute");
            } else {
                [_hiddenjailbreak setUseInjectCompatibilityMode:YES];
                NSLog(@"detected Substrate");
            }

            // Lockdown mode
            if([prefs_lockdown boolForKey:bundleIdentifier]) {
                %init(hook_libc_inject);
                %init(hook_dlopen_inject);

                MSHookFunction((void *) open, (void *) hook_open, (void **) &orig_open);
                MSHookFunction((void *) openat, (void *) hook_openat, (void **) &orig_openat);

                [_hiddenjailbreak setUseInjectCompatibilityMode:NO];
                [_hiddenjailbreak setUseTweakCompatibilityMode:NO];

                _dyld_register_func_for_add_image(dyld_image_added);

                if([prefs boolForKey:@"experimental_enabled"]) {
                    %init(hook_experimental);
                }

                if([prefs boolForKey:@"standardize_paths"]) {
                    [_hiddenjailbreak setUsePathStandardization:YES];
                }

                NSLog(@"enabled lockdown mode");
            }

            if([_hiddenjailbreak useInjectCompatibilityMode]) {
                NSLog(@"using injection compatibility mode");
            } else {
                // Substitute doesn't like hooking opendir :(
                if(!isSubstitute) {
                    MSHookFunction((void *) opendir, (void *) hook_opendir, (void **) &orig_opendir);
                }

                MSHookFunction((void *) readdir, (void *) hook_readdir, (void **) &orig_readdir);
            }

            if([_hiddenjailbreak useTweakCompatibilityMode]) {
                NSLog(@"using tweak compatibility mode");
            }

            // Initialize restricted path map
            init_path_map(_hiddenjailbreak);
            NSLog(@"initialized internal path map");

            // Initialize file map
            NSArray *file_map = [prefs_blacklist objectForKey:@"files"];
            NSArray *url_set = [prefs_blacklist objectForKey:@"schemes"];

            if(file_map) {
                [_hiddenjailbreak addPathsFromFileMap:file_map];

                NSLog(@"initialized file map (%lu items)", (unsigned long) [file_map count]);
            }

            if(url_set) {
                [_hiddenjailbreak addSchemesFromURLSet:url_set];

                NSLog(@"initialized url set (%lu items)", (unsigned long) [url_set count]);
            }

            // Initialize stable hooks
            %init(hook_private);
            %init(hook_NSFileManager);
            %init(hook_NSFileWrapper);
            %init(hook_NSFileVersion);
            %init(hook_libc);
            %init(hook_debugging);
            %init(hook_NSFileHandle);
            %init(hook_NSURL);
            %init(hook_UIApplication);
            %init(hook_NSBundle);
            %init(hook_NSUtilities);
            %init(hook_NSEnumerator);

            MSHookFunction((void *) readlink, (void *) hook_readlink, (void **) &orig_readlink);
            MSHookFunction((void *) readlinkat, (void *) hook_readlinkat, (void **) &orig_readlinkat);

            NSLog(@"hooked bypass methods");

            // Initialize other hooks
            if([prefs boolForKey:@"bypass_checks"]) {
                %init(hook_libraries);

                NSLog(@"hooked detection libraries");
            }

            if([prefs boolForKey:@"dyld_hooks_enabled"]) {
                %init(hook_dyld_image);
                MSHookFunction((void *) dladdr, (void *) hook_dladdr, (void **) &orig_dladdr);

                NSLog(@"filtering dynamic libraries");
            }

            if([prefs boolForKey:@"sandbox_hooks_enabled"]) {
                %init(hook_sandbox);

                NSLog(@"hooked sandbox methods");
            }

            // Generate filtered dyld array
            if([prefs boolForKey:@"dyld_filter_enabled"]) {
                updateDyldArray();

                // %init(hook_dyld_advanced);
                // %init(hook_CoreFoundation);
                %init(hook_runtime);

                NSLog(@"enabled advanced dynamic library filtering");
            }

            if([prefs_dlfcn boolForKey:bundleIdentifier]) {
                %init(hook_dyld_dlsym);

                NSLog(@"hooked dynamic linker methods");
            }

            _error_file_not_found = [HiddenJailbreak generateFileNotFoundError];
            enum_path = [NSMutableDictionary new];

            NSLog(@"ready");
        }
    }
}
