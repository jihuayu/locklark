#import "PassmeCoreBridge.h"
@import Mobilecore;

@interface PMRow ()
@property(nonatomic, readwrite, copy) NSString *identifier;
@property(nonatomic, readwrite, copy) NSString *revision;
@property(nonatomic, readwrite, copy) NSString *title;
@property(nonatomic, readwrite, copy) NSString *state;
@end
@implementation PMRow
@end

@interface PMReceipt ()
@property(nonatomic, readwrite, copy) NSString *identifier;
@property(nonatomic, readwrite, copy) NSString *revision;
@end
@implementation PMReceipt
@end

@interface PMDisclosure ()
@property(nonatomic, readwrite, strong) NSMutableData *data;
@property(nonatomic, readwrite) int64_t fromUnixMilli;
@property(nonatomic, readwrite) int64_t untilUnixMilli;
@end
@implementation PMDisclosure
- (void)clear { [_data resetBytesInRange:NSMakeRange(0, _data.length)]; [_data setLength:0]; }
- (void)dealloc { [self clear]; }
- (NSString *)description { return @"[bounded native disclosure]"; }
@end

@interface PMSecretHandle ()
@property(nonatomic, strong) MobilecoreMobilecoreSecretValue *core;
@end
@implementation PMSecretHandle
- (PMDisclosure *)takeAndReturnError:(NSError **)error {
    NSError *failure = nil;
    NSData *raw = [_core take:&failure];
    if (failure) { if (error) *error = failure; return nil; }
    // gomobile maps successful zero-length Go slices to nil NSData.
    if (!raw) raw = [NSData data];
    PMDisclosure *value = [PMDisclosure new];
    value.data = [raw mutableCopy];
    value.fromUnixMilli = [_core fromUnixMilli];
    value.untilUnixMilli = [_core untilUnixMilli];
    return value;
}
- (void)clear { [_core clear]; }
- (void)dealloc {
    MobilecoreMobilecoreSecretValue *core = _core;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{ [core clear]; });
}
- (NSString *)description { return @"[native secret handle]"; }
@end

@interface PMStoreAdapter : NSObject <MobilecoreMobilecoreSystemUnlockStore>
@property(nonatomic, strong) id<PMSystemUnlockStore> native;
@end
@implementation PMStoreAdapter
- (BOOL)store:(NSString *)identifier value:(NSData *)value error:(NSError **)error { return [_native storeID:identifier data:value error:error]; }
- (NSData *)load:(NSString *)identifier error:(NSError **)error { return [_native loadID:identifier error:error]; }
- (BOOL)delete:(NSString *)identifier error:(NSError **)error { return [_native deleteID:identifier error:error]; }
@end

@interface PMVault ()
@property(nonatomic, strong) MobilecoreMobilecoreVault *core;
@end
@implementation PMVault
+ (instancetype)openAtPath:(NSString *)path error:(NSError **)error {
    MobilecoreMobilecoreVault *core = MobilecoreMobilecoreOpen(path, error);
    if (!core) return nil;
    PMVault *vault = [PMVault new];
    vault.core = core;
    return vault;
}
+ (NSData *)generateSecretKeyAndReturnError:(NSError **)error { return MobilecoreMobilecoreGenerateSecretKey(error); }
+ (NSString *)formatSecretKey:(NSData *)key { return MobilecoreMobilecoreFormatSecretKey(key); }
+ (NSData *)parseSecretKey:(NSString *)text error:(NSError **)error { return MobilecoreMobilecoreParseSecretKey(text, error); }
- (PMVault *)captureOperationAndReturnError:(NSError **)error {
    MobilecoreMobilecoreVault *captured = [_core captureOperation:error];
    if (!captured) return nil;
    PMVault *view = [PMVault new];
    view.core = captured;
    return view;
}
- (BOOL)createWithPassword:(NSData *)password secretKey:(NSData *)key error:(NSError **)error { return [_core create:password secretKey:key error:error]; }
- (BOOL)unlockWithPassword:(NSData *)password secretKey:(NSData *)key error:(NSError **)error { return [_core unlock:password secretKey:key error:error]; }
- (BOOL)isUnlocked { return [_core isUnlocked]; }
- (void)requestLock { [_core requestLock]; }
- (void)lock { [_core lock]; }
- (void)close { [_core close]; }
- (NSArray<PMRow *> *)rowsForQuery:(NSString *)query error:(NSError **)error {
    MobilecoreMobilecoreRows *rows = query.length == 0 ? [_core list:@"active" error:error] : [_core search:query state:@"active" error:error];
    if (!rows) return nil;
    NSMutableArray<PMRow *> *output = [NSMutableArray new];
    for (long i = 0; i < [rows count]; i++) {
        MobilecoreMobilecoreRow *row = [rows at:i error:error];
        if (!row) return nil;
        PMRow *metadata = [PMRow new];
        metadata.identifier = row.id_;
        metadata.revision = row.revision;
        metadata.title = row.title;
        metadata.state = row.state;
        [output addObject:metadata];
    }
    return output;
}
- (PMReceipt *)receipt:(MobilecoreMobilecoreReceipt *)value {
    if (!value) return nil;
    PMReceipt *receipt = [PMReceipt new];
    receipt.identifier = value.id_;
    receipt.revision = value.revision;
    return receipt;
}
- (PMReceipt *)createLoginWithTitle:(NSString *)title URL:(NSString *)url username:(NSData *)username password:(NSData *)password error:(NSError **)error {
    return [self receipt:[_core createLogin:title url:url username:username password:password error:error]];
}
- (PMReceipt *)generateLoginWithTitle:(NSString *)title URL:(NSString *)url username:(NSData *)username length:(NSInteger)length error:(NSError **)error {
    return [self receipt:[_core generateLogin:title url:url username:username length:length error:error]];
}
- (PMReceipt *)editID:(NSString *)identifier revision:(NSString *)revision field:(NSString *)field value:(NSData *)value error:(NSError **)error {
    return [self receipt:[_core editField:identifier revision:revision field:field value:value error:error]];
}
- (PMReceipt *)regenerateID:(NSString *)identifier revision:(NSString *)revision length:(NSInteger)length error:(NSError **)error {
    return [self receipt:[_core regeneratePassword:identifier revision:revision length:length error:error]];
}
- (PMSecretHandle *)revealID:(NSString *)identifier revision:(NSString *)revision field:(NSString *)field error:(NSError **)error {
    MobilecoreMobilecoreSecretValue *value = [field isEqualToString:@"otp-code"] ? [_core revealOTP:identifier revision:revision error:error] : [_core revealField:identifier revision:revision field:field error:error];
    if (!value) return nil;
    PMSecretHandle *handle = [PMSecretHandle new];
    handle.core = value;
    return handle;
}
- (PMStoreAdapter *)adapter:(id<PMSystemUnlockStore>)store { PMStoreAdapter *adapter = [PMStoreAdapter new]; adapter.native = store; return adapter; }
- (BOOL)enableSystemUnlock:(id<PMSystemUnlockStore>)store error:(NSError **)error { return [_core enableSystemUnlock:[self adapter:store] error:error]; }
- (BOOL)unlockWithSystem:(id<PMSystemUnlockStore>)store error:(NSError **)error { return [_core unlockWithSystem:[self adapter:store] error:error]; }
- (BOOL)disableSystemUnlock:(id<PMSystemUnlockStore>)store error:(NSError **)error { return [_core disableSystemUnlock:[self adapter:store] error:error]; }
- (NSString *)description { return @"[native vault]"; }
@end
