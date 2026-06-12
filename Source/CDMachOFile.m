// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDMachOFile.h"

#include <mach-o/arch.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/fixup-chains.h>

#import "CDMachOFileDataCursor.h"
#import "CDFatFile.h"
#import "CDLoadCommand.h"
#import "CDLCDyldInfo.h"
#import "CDLCLinkeditData.h"
#import "CDLCDylib.h"
#import "CDLCDynamicSymbolTable.h"
#import "CDLCEncryptionInfo.h"
#import "CDLCRunPath.h"
#import "CDLCSegment.h"
#import "CDLCSymbolTable.h"
#import "CDLCUUID.h"
#import "CDLCVersionMinimum.h"
#import "CDObjectiveC1Processor.h"
#import "CDObjectiveC2Processor.h"
#import "CDSection.h"
#import "CDSymbol.h"
#import "CDRelocationInfo.h"
#import "CDSearchPathState.h"
#import "CDLCSourceVersion.h"
#import "CDLCBuildVersion.h"

static NSString *CDMachOFileMagicNumberDescription(uint32_t magic)
{
    switch (magic) {
        case MH_MAGIC:    return @"MH_MAGIC";
        case MH_CIGAM:    return @"MH_CIGAM";
        case MH_MAGIC_64: return @"MH_MAGIC_64";
        case MH_CIGAM_64: return @"MH_CIGAM_64";
    }

    return [NSString stringWithFormat:@"0x%08x", magic];
}

@implementation CDMachOFile
{
    CDByteOrder _byteOrder;
    
    NSArray *_loadCommands;
    NSArray *_dylibLoadCommands;
    NSArray *_segments;
    CDLCSymbolTable *_symbolTable;
    CDLCDynamicSymbolTable *_dynamicSymbolTable;
    CDLCDyldInfo *_dyldInfo;
    CDLCDylib *_dylibIdentifier;
    CDLCVersionMinimum *_minVersionMacOSX;
    CDLCVersionMinimum *_minVersionIOS;
    CDLCSourceVersion *_sourceVersion;
    CDLCBuildVersion *_buildVersion;
    NSArray *_runPaths;
    NSArray *_runPathCommands;
    NSArray *_dyldEnvironment;
    NSArray *_reExportedDylibs;

    CDLCLinkeditData *_chainedFixups;             // LC_DYLD_CHAINED_FIXUPS command, if present.
    NSDictionary *_chainedFixupSymbolNames;       // address (NSNumber) -> imported symbol name (NSString).

    // The parts of struct mach_header_64 pulled out so that our property accessors can be synthesized.
	uint32_t _magic;
	cpu_type_t _cputype;
	cpu_subtype_t _cpusubtype;
	uint32_t _filetype;
	uint32_t _ncmds;
	uint32_t _sizeofcmds;
	uint32_t _flags;
	uint32_t _reserved;
    
    BOOL _uses64BitABI;
}

- (id)init;
{
    if ((self = [super init])) {
        _byteOrder = CDByteOrder_LittleEndian;
    }
    
    return self;
}

- (id)initWithData:(NSData *)data filename:(NSString *)filename searchPathState:(CDSearchPathState *)searchPathState;
{
    if ((self = [super initWithData:data filename:filename searchPathState:searchPathState])) {
        _byteOrder = CDByteOrder_LittleEndian;
        
        CDDataCursor *cursor = [[CDDataCursor alloc] initWithData:data];
        _magic = [cursor readBigInt32];
        if (_magic == MH_MAGIC || _magic == MH_MAGIC_64) {
            _byteOrder = CDByteOrder_BigEndian;
        } else if (_magic == MH_CIGAM || _magic == MH_CIGAM_64) {
            _byteOrder = CDByteOrder_LittleEndian;
        } else {
            return nil;
        }
        
        _uses64BitABI = (_magic == MH_MAGIC_64) || (_magic == MH_CIGAM_64);
        
        if (_byteOrder == CDByteOrder_LittleEndian) {
            _cputype    = [cursor readLittleInt32];
            _cpusubtype = [cursor readLittleInt32];
            _filetype   = [cursor readLittleInt32];
            _ncmds      = [cursor readLittleInt32];
            _sizeofcmds = [cursor readLittleInt32];
            _flags      = [cursor readLittleInt32];
            if (_uses64BitABI) {
                _reserved = [cursor readLittleInt32];
            }
        } else {
            _cputype    = [cursor readBigInt32];
            _cpusubtype = [cursor readBigInt32];
            _filetype   = [cursor readBigInt32];
            _ncmds      = [cursor readBigInt32];
            _sizeofcmds = [cursor readBigInt32];
            _flags      = [cursor readBigInt32];
            if (_uses64BitABI) {
                _reserved = [cursor readBigInt32];
            }
        }
        
        NSAssert(_uses64BitABI == CDArchUses64BitABI((CDArch){ .cputype = _cputype, .cpusubtype = _cpusubtype }), @"Header magic should match cpu arch", nil);
        
        NSUInteger headerOffset = _uses64BitABI ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
        CDMachOFileDataCursor *fileCursor = [[CDMachOFileDataCursor alloc] initWithFile:self offset:headerOffset];
        [self _readLoadCommands:fileCursor count:_ncmds];
    }

    return self;
}

- (void)_readLoadCommands:(CDMachOFileDataCursor *)cursor count:(uint32_t)count;
{
    NSMutableArray *loadCommands      = [[NSMutableArray alloc] init];
    NSMutableArray *dylibLoadCommands = [[NSMutableArray alloc] init];
    NSMutableArray *segments          = [[NSMutableArray alloc] init];
    NSMutableArray *runPaths          = [[NSMutableArray alloc] init];
    NSMutableArray *runPathCommands   = [[NSMutableArray alloc] init];
    NSMutableArray *dyldEnvironment   = [[NSMutableArray alloc] init];
    NSMutableArray *reExportedDylibs  = [[NSMutableArray alloc] init];
    
    for (uint32_t index = 0; index < count; index++) {
        CDLoadCommand *loadCommand = [CDLoadCommand loadCommandWithDataCursor:cursor];
        if (loadCommand != nil) {
            [loadCommands addObject:loadCommand];

            if (loadCommand.cmd == LC_VERSION_MIN_MACOSX)                        self.minVersionMacOSX = (CDLCVersionMinimum *)loadCommand;
            if (loadCommand.cmd == LC_VERSION_MIN_IPHONEOS)                      self.minVersionIOS = (CDLCVersionMinimum *)loadCommand;
            if (loadCommand.cmd == LC_DYLD_ENVIRONMENT)                          [dyldEnvironment addObject:loadCommand];
            if (loadCommand.cmd == LC_REEXPORT_DYLIB)                            [reExportedDylibs addObject:loadCommand];
            if (loadCommand.cmd == LC_ID_DYLIB)                                  self.dylibIdentifier = (CDLCDylib *)loadCommand;
            if (loadCommand.cmd == LC_DYLD_CHAINED_FIXUPS)                       _chainedFixups = (CDLCLinkeditData *)loadCommand;

            if ([loadCommand isKindOfClass:[CDLCSourceVersion class]])           self.sourceVersion = (CDLCSourceVersion *)loadCommand;
            else if ([loadCommand isKindOfClass:[CDLCBuildVersion class]])       self.buildVersion = (CDLCBuildVersion *)loadCommand;
            else if ([loadCommand isKindOfClass:[CDLCDylib class]])              [dylibLoadCommands addObject:loadCommand];
            else if ([loadCommand isKindOfClass:[CDLCSegment class]])            [segments addObject:loadCommand];
            else if ([loadCommand isKindOfClass:[CDLCSymbolTable class]])        self.symbolTable = (CDLCSymbolTable *)loadCommand;
            else if ([loadCommand isKindOfClass:[CDLCDynamicSymbolTable class]]) self.dynamicSymbolTable = (CDLCDynamicSymbolTable *)loadCommand;
            else if ([loadCommand isKindOfClass:[CDLCDyldInfo class]])           self.dyldInfo = (CDLCDyldInfo *)loadCommand;
            else if ([loadCommand isKindOfClass:[CDLCRunPath class]]) {
                [runPaths addObject:[(CDLCRunPath *)loadCommand resolvedRunPath]];
                [runPathCommands addObject:loadCommand];
            }
        }
        //NSLog(@"loadCommand: %@", loadCommand);
    }
    _loadCommands      = [loadCommands copy];
    _dylibLoadCommands = [dylibLoadCommands copy];
    _segments          = [segments copy];
    _runPaths          = [runPaths copy];
    _runPathCommands   = [runPathCommands copy];
    _dyldEnvironment   = [dyldEnvironment copy];
    _reExportedDylibs  = [reExportedDylibs copy];

    for (CDLoadCommand *loadCommand in _loadCommands) {
        [loadCommand machOFileDidReadLoadCommands:self];
    }

    if (_chainedFixups != nil)
        [self _processChainedFixups];
}

#pragma mark - Debugging

- (NSString *)description;
{
    return [NSString stringWithFormat:@"<%@:%p> magic: 0x%08x, cputype: %x, cpusubtype: %x, filetype: %d, ncmds: %ld, sizeofcmds: %d, flags: 0x%x, uses64BitABI? %d, filename: %@, data: %p",
            NSStringFromClass([self class]), self,
            [self magic], [self cputype], [self cpusubtype], [self filetype], [_loadCommands count], 0, [self flags], self.uses64BitABI,
            self.filename, self.data];
}

#pragma mark -

- (CDMachOFile *)machOFileWithArch:(CDArch)arch;
{
    if (self.cputype == arch.cputype && self.maskedCPUSubtype == (arch.cpusubtype & ~CPU_SUBTYPE_MASK))
        return self;

    return nil;
}

#pragma mark -

- (cpu_type_t)maskedCPUType;
{
    return self.cputype & ~CPU_ARCH_MASK;
}

- (cpu_subtype_t)maskedCPUSubtype;
{
    return self.cpusubtype & ~CPU_SUBTYPE_MASK;
}

- (NSUInteger)ptrSize;
{
    return self.uses64BitABI ? sizeof(uint64_t) : sizeof(uint32_t);
}
             
// We only have one architecture, so it is by default the best match.  
- (BOOL)bestMatchForArch:(CDArch *)ioArchPtr;
{
    if (ioArchPtr != NULL) {
        ioArchPtr->cputype    = self.cputype;
        ioArchPtr->cpusubtype = self.cpusubtype;
    }

    return YES;
}

- (NSString *)filetypeDescription;
{
    switch ([self filetype]) {
        case MH_OBJECT:      return @"OBJECT";
        case MH_EXECUTE:     return @"EXECUTE";
        case MH_FVMLIB:      return @"FVMLIB";
        case MH_CORE:        return @"CORE";
        case MH_PRELOAD:     return @"PRELOAD";
        case MH_DYLIB:       return @"DYLIB";
        case MH_DYLINKER:    return @"DYLINKER";
        case MH_BUNDLE:      return @"BUNDLE";
        case MH_DYLIB_STUB:  return @"DYLIB_STUB";
        case MH_DSYM:        return @"DSYM";
        case MH_KEXT_BUNDLE: return @"KEXT_BUNDLE";
        default:
            break;
    }

    return nil;
}

- (NSString *)flagDescription;
{
    NSMutableArray *setFlags = [NSMutableArray array];
    uint32_t flags = [self flags];
    if (flags & MH_NOUNDEFS)                [setFlags addObject:@"NOUNDEFS"];
    if (flags & MH_INCRLINK)                [setFlags addObject:@"INCRLINK"];
    if (flags & MH_DYLDLINK)                [setFlags addObject:@"DYLDLINK"];
    if (flags & MH_BINDATLOAD)              [setFlags addObject:@"BINDATLOAD"];
    if (flags & MH_PREBOUND)                [setFlags addObject:@"PREBOUND"];
    if (flags & MH_SPLIT_SEGS)              [setFlags addObject:@"SPLIT_SEGS"];
    if (flags & MH_LAZY_INIT)               [setFlags addObject:@"LAZY_INIT"];
    if (flags & MH_TWOLEVEL)                [setFlags addObject:@"TWOLEVEL"];
    if (flags & MH_FORCE_FLAT)              [setFlags addObject:@"FORCE_FLAT"];
    if (flags & MH_NOMULTIDEFS)             [setFlags addObject:@"NOMULTIDEFS"];
    if (flags & MH_NOFIXPREBINDING)         [setFlags addObject:@"NOFIXPREBINDING"];
    if (flags & MH_PREBINDABLE)             [setFlags addObject:@"PREBINDABLE"];
    if (flags & MH_ALLMODSBOUND)            [setFlags addObject:@"ALLMODSBOUND"];
    if (flags & MH_SUBSECTIONS_VIA_SYMBOLS) [setFlags addObject:@"SUBSECTIONS_VIA_SYMBOLS"];
    if (flags & MH_CANONICAL)               [setFlags addObject:@"CANONICAL"];
    if (flags & MH_WEAK_DEFINES)            [setFlags addObject:@"WEAK_DEFINES"];
    if (flags & MH_BINDS_TO_WEAK)           [setFlags addObject:@"BINDS_TO_WEAK"];
    if (flags & MH_ALLOW_STACK_EXECUTION)   [setFlags addObject:@"ALLOW_STACK_EXECUTION"];
    if (flags & MH_ROOT_SAFE)               [setFlags addObject:@"ROOT_SAFE"];
    if (flags & MH_SETUID_SAFE)             [setFlags addObject:@"SETUID_SAFE"];
    if (flags & MH_NO_REEXPORTED_DYLIBS)    [setFlags addObject:@"NO_REEXPORTED_DYLIBS"];
    if (flags & MH_PIE)                     [setFlags addObject:@"PIE"];

    return [setFlags componentsJoinedByString:@" "];
}

#pragma mark -

- (CDLCSegment *)dataConstSegment
{
    // macho objects from iOS 9 appear to store various sections
    // in __DATA_CONST that were previously found in __DATA
    CDLCSegment *seg = [self segmentWithName:@"__DATA_CONST"];

    // Fall back on __DATA if it is not found for earlier behavior
    if (!seg) {
        seg = [self segmentWithName:@"__DATA"];
    }
    return seg;
}

- (CDLCSegment *)segmentWithName:(NSString *)segmentName;
{
    for (id loadCommand in _loadCommands) {
        if ([loadCommand isKindOfClass:[CDLCSegment class]] && [[loadCommand name] isEqual:segmentName]) {
            return loadCommand;
        }
    }

    return nil;
}

- (CDLCSegment *)segmentContainingAddress:(NSUInteger)address;
{
    for (id loadCommand in _loadCommands) {
        if ([loadCommand isKindOfClass:[CDLCSegment class]] && [loadCommand containsAddress:address]) {
            return loadCommand;
        }
    }

    return nil;
}

- (void)showWarning:(NSString *)warning;
{
    NSLog(@"Warning: %@", warning);
}

- (NSString *)stringAtAddress:(NSUInteger)address;
{
    const void *ptr;

    if (address == 0)
        return nil;

    CDLCSegment *segment = [self segmentContainingAddress:address];
    if (segment == nil) {
        NSLog(@"Error: Cannot find offset for address 0x%08lx in stringAtAddress:", address);
        exit(5);
        return nil;
    }

    if ([segment isProtected]) {
        NSData *d2 = [segment decryptedData];
        NSUInteger d2Offset = [segment segmentOffsetForAddress:address];
        if (d2Offset == 0)
            return nil;

        ptr = (uint8_t *)[d2 bytes] + d2Offset;
        return [[NSString alloc] initWithBytes:ptr length:strlen(ptr) encoding:NSASCIIStringEncoding];
    }

    NSUInteger offset = [self dataOffsetForAddress:address];
    if (offset == 0)
        return nil;

    ptr = (uint8_t *)[self.data bytes] + offset;

    return [[NSString alloc] initWithBytes:ptr length:strlen(ptr) encoding:NSASCIIStringEncoding];
}

- (NSUInteger)dataOffsetForAddress:(NSUInteger)address;
{
    if (address == 0)
        return 0;

    CDLCSegment *segment = [self segmentContainingAddress:address];
    if (segment == nil) {
        NSLog(@"Error: Cannot find offset for address 0x%08lx in dataOffsetForAddress:", address);
        exit(5);
    }

//    if ([segment isProtected]) {
//        NSLog(@"Error: Segment is protected.");
//        exit(5);
//    }

#if 0
    NSLog(@"---------->");
    NSLog(@"segment is: %@", segment);
    NSLog(@"address: 0x%08x", address);
    NSLog(@"CDFile offset:    0x%08x", offset);
    NSLog(@"file off for address: 0x%08x", [segment fileOffsetForAddress:address]);
    NSLog(@"data offset:      0x%08x", offset + [segment fileOffsetForAddress:address]);
    NSLog(@"<----------");
#endif
    return [segment fileOffsetForAddress:address];
}

- (const void *)bytes;
{
    return [self.data bytes];
}

- (const void *)bytesAtOffset:(NSUInteger)offset;
{
    return (uint8_t *)[self.data bytes] + offset;
}

- (NSString *)importBaseName;
{
    if ([self filetype] == MH_DYLIB) {
        return CDImportNameForPath(self.filename);
    }

    return nil;
}

#pragma mark -

- (BOOL)isEncrypted;
{
    for (CDLoadCommand *loadCommand in _loadCommands) {
        if ([loadCommand isKindOfClass:[CDLCEncryptionInfo class]] && [(CDLCEncryptionInfo *)loadCommand isEncrypted]) {
            return YES;
        }
    }

    return NO;
}

- (BOOL)hasProtectedSegments;
{
    for (CDLoadCommand *loadCommand in _loadCommands) {
        if ([loadCommand isKindOfClass:[CDLCSegment class]] && [(CDLCSegment *)loadCommand isProtected])
            return YES;
    }

    return NO;
}

- (BOOL)canDecryptAllSegments;
{
    for (CDLoadCommand *loadCommand in _loadCommands) {
        if ([loadCommand isKindOfClass:[CDLCSegment class]] && [(CDLCSegment *)loadCommand canDecrypt] == NO)
            return NO;
    }

    return YES;
}

- (NSString *)loadCommandString:(BOOL)isVerbose;
{
    NSMutableString *resultString = [NSMutableString string];
    NSUInteger count = [_loadCommands count];
    for (NSUInteger index = 0; index < count; index++) {
        [resultString appendFormat:@"Load command %lu\n", index];
        CDLoadCommand *loadCommand = _loadCommands[index];
        [loadCommand appendToString:resultString verbose:isVerbose];
        [resultString appendString:@"\n"];
    }

    return resultString;
}

- (NSString *)headerString:(BOOL)isVerbose;
{
    NSMutableString *resultString = [NSMutableString string];
    [resultString appendString:@"Mach header\n"];
    [resultString appendString:@"      magic cputype cpusubtype   filetype ncmds sizeofcmds      flags\n"];
    // Grr, %11@ doesn't work.
    if (isVerbose)
        [resultString appendFormat:@"%11@ %7@ %10u   %8@ %5lu %10u %@\n",
                      CDMachOFileMagicNumberDescription([self magic]), [self archName], [self cpusubtype],
                      [self filetypeDescription], [_loadCommands count], 0, [self flagDescription]];
    else
        [resultString appendFormat:@" 0x%08x %7u %10u   %8u %5lu %10u 0x%08x\n",
                      [self magic], [self cputype], [self cpusubtype], [self filetype], [_loadCommands count], 0, [self flags]];
    [resultString appendString:@"\n"];

    return resultString;
}

- (NSUUID *)UUID;
{
    for (CDLoadCommand *loadCommand in _loadCommands)
        if ([loadCommand isKindOfClass:[CDLCUUID class]])
            return [(CDLCUUID *)loadCommand UUID];

    return nil;
}

// Must not return nil.
- (NSString *)archName;
{
    return CDNameForCPUType([self cputype], [self cpusubtype]);
}

- (void)logInfoForAddress:(NSUInteger)address;
{
    if (address != 0) {
        CDLCSegment *segment = [self segmentContainingAddress:address];
        if (segment == nil) {
            NSLog(@"No segment contains address: %016lx", address);
        } else {
            //NSLog(@"Found address %016lx in segment, sections= %@", address, [segment sections]);
            CDSection *section = [segment sectionContainingAddress:address];
            if (section == nil) {
                NSLog(@"Found address %016lx in segment %@, but not in a section", address, [segment name]);
            } else {
                NSLog(@"Found address %016lx in segment %@, section %@", address, [segment name], [section sectionName]);
            }
        }

        NSString *str = [self stringAtAddress:address];
        NSLog(@"      address %016lx as a string: '%@' (length %lu)", address, str, [str length]);
        NSLog(@"      address %016lx data offset: %lu", address, [self dataOffsetForAddress:address]);
    }
}

- (NSString *)externalClassNameForAddress:(NSUInteger)address;
{
    // Not for NSCFArray (NSMutableArray), NSSimpleAttributeDictionaryEnumerator (NSEnumerator), NSSimpleAttributeDictionary (NSDictionary), etc.
    // It turns out NSMutableArray is in /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation, so...
    // ... it's an undefined symbol, need to look it up.
    CDRelocationInfo *rinfo = [self.dynamicSymbolTable relocationEntryWithOffset:address - [self.symbolTable baseAddress]];
    //NSLog(@"rinfo: %@", rinfo);
    if (rinfo != nil) {
        CDSymbol *symbol = [[self.symbolTable symbols] objectAtIndex:rinfo.symbolnum];
        //NSLog(@"symbol: %@", symbol);

        // Now we could use GET_LIBRARY_ORDINAL(), look up the the appropriate mach-o file (being sure to have loaded them even without -r),
        // look up the symbol in that mach-o file, get the address, look up the class based on that address, and finally get the class name
        // from that.

        // Or, we could be lazy and take advantage of the fact that the class name we're after is in the symbol name:
        NSString *str = [symbol name];
        if ([str hasPrefix:ObjCClassSymbolPrefix]) {
            return [str substringFromIndex:[ObjCClassSymbolPrefix length]];
        } else {
            NSLog(@"Warning: Unknown prefix on symbol name... %@ (addr %lx)", str, address);
            return str;
        }
    }

    // This is fine, they might really be root objects.  NSObject, NSProxy.
    return nil;
}

- (BOOL)hasRelocationEntryForAddress:(NSUInteger)address;
{
    CDRelocationInfo *rinfo = [self.dynamicSymbolTable relocationEntryWithOffset:address - [self.symbolTable baseAddress]];
    //NSLog(@"%s, rinfo= %@", __cmd, rinfo);
    return rinfo != nil;
}

- (BOOL)hasRelocationEntryForAddress2:(NSUInteger)address;
{
    if (_chainedFixupSymbolNames[@(address)] != nil)
        return YES;
    return [self.dyldInfo symbolNameForAddress:address] != nil;
}

- (NSString *)externalClassNameForAddress2:(NSUInteger)address;
{
    NSString *str = _chainedFixupSymbolNames[@(address)];
    if (str == nil)
        str = [self.dyldInfo symbolNameForAddress:address];

    if (str != nil) {
        if ([str hasPrefix:ObjCClassSymbolPrefix]) {
            return [str substringFromIndex:[ObjCClassSymbolPrefix length]];
        } else {
            NSLog(@"Warning: Unknown prefix on symbol name... %@ (addr %lx)", str, address);
            return str;
        }
    }

    return nil;
}

#pragma mark - Dyld chained fixups

// Modern Mach-O files (LC_DYLD_CHAINED_FIXUPS) no longer store rebase/bind information as a stream of
// dyld_info opcodes.  Instead, the pointers in the data segments are themselves a linked list of "chains"
// where each entry encodes either a rebase (an offset into this image) or a bind (an index into an imports
// table of external symbols).  The rest of class-dump assumes the old behaviour, where on-disk pointers hold
// real VM addresses, so here we walk the chains and rewrite each pointer in place: rebases become the real
// VM address, binds become 0 (with the imported symbol name recorded for later superclass resolution).
- (void)_processChainedFixups;
{
    NSData *blob = [_chainedFixups linkeditData];
    if (blob.length < sizeof(struct dyld_chained_fixups_header))
        return;

    const uint8_t *cd = (const uint8_t *)blob.bytes;
    const struct dyld_chained_fixups_header *header = (const struct dyld_chained_fixups_header *)cd;

    // The image base is the VM address of the __TEXT segment (offset-based pointer formats are relative to it).
    CDLCSegment *textSegment = [self segmentWithName:@"__TEXT"];
    uint64_t imageBase = textSegment != nil ? (uint64_t)textSegment.vmaddr : 0;

    // Build the table of imported symbol names, indexed by import ordinal.
    NSMutableArray *importNames = [NSMutableArray array];
    {
        const char *symbolPool = (const char *)(cd + header->symbols_offset);
        const void *imports = cd + header->imports_offset;
        for (uint32_t index = 0; index < header->imports_count; index++) {
            uint32_t nameOffset = 0;
            switch (header->imports_format) {
                case DYLD_CHAINED_IMPORT: {
                    struct dyld_chained_import entry = ((const struct dyld_chained_import *)imports)[index];
                    nameOffset = entry.name_offset;
                    break;
                }
                case DYLD_CHAINED_IMPORT_ADDEND: {
                    struct dyld_chained_import_addend entry = ((const struct dyld_chained_import_addend *)imports)[index];
                    nameOffset = entry.name_offset;
                    break;
                }
                case DYLD_CHAINED_IMPORT_ADDEND64: {
                    struct dyld_chained_import_addend64 entry = ((const struct dyld_chained_import_addend64 *)imports)[index];
                    nameOffset = (uint32_t)entry.name_offset;
                    break;
                }
                default:
                    break;
            }
            NSString *name = [NSString stringWithUTF8String:symbolPool + nameOffset] ?: @"";
            [importNames addObject:name];
        }
    }

    NSMutableData *mutableData = [self mutableData];
    uint8_t *fileBytes = (uint8_t *)mutableData.mutableBytes;
    NSMutableDictionary *symbolNames = [NSMutableDictionary dictionary];

    const struct dyld_chained_starts_in_image *startsInImage = (const struct dyld_chained_starts_in_image *)(cd + header->starts_offset);
    for (uint32_t segmentIndex = 0; segmentIndex < startsInImage->seg_count; segmentIndex++) {
        uint32_t segInfoOffset = startsInImage->seg_info_offset[segmentIndex];
        if (segInfoOffset == 0)
            continue;

        const struct dyld_chained_starts_in_segment *segInfo = (const struct dyld_chained_starts_in_segment *)((const uint8_t *)startsInImage + segInfoOffset);
        uint16_t pointerFormat = segInfo->pointer_format;
        BOOL isArm64e = (pointerFormat == DYLD_CHAINED_PTR_ARM64E ||
                         pointerFormat == DYLD_CHAINED_PTR_ARM64E_KERNEL ||
                         pointerFormat == DYLD_CHAINED_PTR_ARM64E_USERLAND ||
                         pointerFormat == DYLD_CHAINED_PTR_ARM64E_FIRMWARE ||
                         pointerFormat == DYLD_CHAINED_PTR_ARM64E_USERLAND24);
        // The "next" field of each pointer is a count of strides to the following pointer in the chain.
        uint32_t stride = (pointerFormat == DYLD_CHAINED_PTR_ARM64E ||
                           pointerFormat == DYLD_CHAINED_PTR_ARM64E_USERLAND ||
                           pointerFormat == DYLD_CHAINED_PTR_ARM64E_USERLAND24) ? 8 : 4;

        if (pointerFormat != DYLD_CHAINED_PTR_64 &&
            pointerFormat != DYLD_CHAINED_PTR_64_OFFSET &&
            !isArm64e) {
            NSLog(@"Warning: Unsupported dyld chained pointer format %u; skipping segment.", pointerFormat);
            continue;
        }

        for (uint16_t pageIndex = 0; pageIndex < segInfo->page_count; pageIndex++) {
            uint16_t startOffset = segInfo->page_start[pageIndex];
            if (startOffset == DYLD_CHAINED_PTR_START_NONE)
                continue;
            if (startOffset & DYLD_CHAINED_PTR_START_MULTI) {
                NSLog(@"Warning: dyld chained fixups with multiple starts per page are not supported.");
                continue;
            }

            uint64_t chainAddress = imageBase + segInfo->segment_offset + (uint64_t)pageIndex * segInfo->page_size + startOffset;
            BOOL done = NO;
            while (!done) {
                NSUInteger fileOffset = [self dataOffsetForAddress:chainAddress];
                uint64_t raw = *(const uint64_t *)(fileBytes + fileOffset);

                uint64_t next;
                BOOL isBind;
                uint64_t newValue = 0;
                BOOL writeValue = YES;

                if (isArm64e) {
                    isBind = (raw >> 62) & 0x1;
                    BOOL isAuth = (raw >> 63) & 0x1;
                    next = (raw >> 51) & 0x7ff;
                    if (isBind) {
                        uint64_t ordinal = (pointerFormat == DYLD_CHAINED_PTR_ARM64E_USERLAND24) ? (raw & 0xffffff) : (raw & 0xffff);
                        if (ordinal < importNames.count)
                            symbolNames[@(chainAddress)] = importNames[(NSUInteger)ordinal];
                        newValue = 0;
                    } else if (isAuth) {
                        uint64_t target = raw & 0xffffffff;
                        newValue = imageBase + target;
                    } else {
                        uint64_t target = raw & 0x7ffffffffff; // 43 bits
                        newValue = (pointerFormat == DYLD_CHAINED_PTR_ARM64E) ? target : imageBase + target;
                    }
                } else {
                    // DYLD_CHAINED_PTR_64 or DYLD_CHAINED_PTR_64_OFFSET
                    isBind = (raw >> 63) & 0x1;
                    next = (raw >> 51) & 0xfff;
                    if (isBind) {
                        uint64_t ordinal = raw & 0xffffff; // 24 bits
                        if (ordinal < importNames.count)
                            symbolNames[@(chainAddress)] = importNames[(NSUInteger)ordinal];
                        newValue = 0;
                    } else {
                        uint64_t target = raw & 0xfffffffff; // 36 bits
                        newValue = (pointerFormat == DYLD_CHAINED_PTR_64) ? target : imageBase + target;
                    }
                }

                if (writeValue)
                    *(uint64_t *)(fileBytes + fileOffset) = newValue;

                if (next == 0)
                    done = YES;
                else
                    chainAddress += next * stride;
            }
        }
    }

    _chainedFixupSymbolNames = [symbolNames copy];
}

- (BOOL)hasObjectiveC1Data;
{
    return [self segmentWithName:@"__OBJC"] != nil;
}

- (BOOL)hasObjectiveC2Data;
{
    // http://twitter.com/gparker/status/17962955683
    // Oxced: What's the best way to determine the ObjC ABI version of a file?  otool tests if cputype is ARM, but that's not accurate with iOS 4 simulator
    // gparker: @0xced Old ABI has an __OBJC segment. New ABI has a __DATA,__objc_info section.
    // 0xced: @gparker I was hoping for a flag, but that will do it, thanks.
    // 0xced: @gparker Did you mean __DATA,__objc_imageinfo instead of __DATA,__objc_info ?
    // gparker: @0xced Yes, it's __DATA,__objc_imageinfo.
    return [[self dataConstSegment] sectionWithName:@"__objc_imageinfo"] != nil;
}

- (Class)processorClass;
{
    if ([self hasObjectiveC2Data])
        return [CDObjectiveC2Processor class];
    
    return [CDObjectiveC1Processor class];
}

- (CDLCDylib *)dylibLoadCommandForLibraryOrdinal:(NSUInteger)libraryOrdinal;
{
    if (libraryOrdinal == SELF_LIBRARY_ORDINAL || libraryOrdinal >= MAX_LIBRARY_ORDINAL)
        return nil;
    
    NSArray *loadCommands = _dylibLoadCommands;
    if (_dylibIdentifier != nil) {
        // Remove our own ID (LC_ID_DYLIB) so that we calculate the correct offset
        NSMutableArray *remainingLoadCommands = [loadCommands mutableCopy];
        [remainingLoadCommands removeObject:_dylibIdentifier];
        loadCommands = remainingLoadCommands;
    }
    
    if (libraryOrdinal - 1 < [loadCommands count]) // Ordinals start from 1
        return loadCommands[libraryOrdinal - 1];
    else
        return nil;
}

- (NSString *)architectureNameDescription;
{
    return self.archName;
}

@end
