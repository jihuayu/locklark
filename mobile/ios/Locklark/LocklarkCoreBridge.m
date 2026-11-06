#import "LocklarkCoreBridge.h"
@import Mobilecore;

@interface LLRow ()
@property(nonatomic, readwrite, copy) NSString *identifier;
@property(nonatomic, readwrite, copy) NSString *revision;
@property(nonatomic, readwrite, copy) NSString *title;
@property(nonatomic, readwrite, copy) NSString *state;
@end
@implementation LLRow
@end

@interface LLReceipt ()
@property(nonatomic, readwrite, copy) NSString *identifier;
@property(nonatomic, readwrite, copy) NSString *revision;
@end
@implementation LLReceipt
@end

@interface LLDisclosure ()
@property(nonatomic, readwrite, strong) NSMutableData *data;
@property(nonatomic, readwrite) int64_t fromUnixMilli;
@property(nonatomic, readwrite) int64_t untilUnixMilli;
@end
@implementation LLDisclosure
- (void)clear { [_data resetBytesInRange:NSMakeRange(0, _data.length)]; [_data setLength:0]; }
- (void)dealloc { [self clear]; }
- (NSString *)description { return @"[bounded native disclosure]"; }
@end

@interface LLSecretHandle ()
@property(nonatomic, strong) MobilecoreMobilecoreSecretValue *core;
@end
@implementation LLSecretHandle
- (LLDisclosure *)takeAndReturnError:(NSError **)error {
    NSError *failure = nil;
    NSData *raw = [_core take:&failure];
    if (failure) { if (error) *error = failure; return nil; }
    // gomobile maps successful zero-length Go slices to nil NSData.
    if (!raw) raw = [NSData data];
    LLDisclosure *value = [LLDisclosure new];
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

@interface LLStoreAdapter : NSObject <MobilecoreMobilecoreSystemUnlockStore>
@property(nonatomic, strong) id<LLSystemUnlockStore> native;
@end
@implementation LLStoreAdapter
- (BOOL)store:(NSString *)identifier value:(NSData *)value error:(NSError **)error { return [_native storeID:identifier data:value error:error]; }
- (NSData *)load:(NSString *)identifier error:(NSError **)error { return [_native loadID:identifier error:error]; }
- (BOOL)delete:(NSString *)identifier error:(NSError **)error { return [_native deleteID:identifier error:error]; }
@end

@interface LLVault ()
@property(nonatomic, strong) MobilecoreMobilecoreVault *core;
@end
@implementation LLVault
+ (instancetype)openAtPath:(NSString *)path error:(NSError **)error {
    MobilecoreMobilecoreVault *core = MobilecoreMobilecoreOpen(path, error);
    if (!core) return nil;
    LLVault *vault = [LLVault new];
    vault.core = core;
    return vault;
}
+ (NSData *)generateSecretKeyAndReturnError:(NSError **)error { return MobilecoreMobilecoreGenerateSecretKey(error); }
+ (NSString *)formatSecretKey:(NSData *)key { return MobilecoreMobilecoreFormatSecretKey(key); }
+ (NSData *)parseSecretKey:(NSString *)text error:(NSError **)error { return MobilecoreMobilecoreParseSecretKey(text, error); }
- (BOOL)createWithPassword:(NSData *)password secretKey:(NSData *)key error:(NSError **)error { return [_core create:password secretKey:key error:error]; }
- (BOOL)unlockWithPassword:(NSData *)password secretKey:(NSData *)key error:(NSError **)error { return [_core unlock:password secretKey:key error:error]; }
- (BOOL)isUnlocked { return [_core isUnlocked]; }
- (void)requestLock { [_core requestLock]; }
- (void)lock { [_core lock]; }
- (void)close { [_core close]; }
- (NSArray<LLRow *> *)rowsForQuery:(NSString *)query error:(NSError **)error {
    MobilecoreMobilecoreRows *rows = query.length == 0 ? [_core list:@"active" error:error] : [_core search:query state:@"active" error:error];
    if (!rows) return nil;
    NSMutableArray<LLRow *> *output = [NSMutableArray new];
    for (long i = 0; i < [rows count]; i++) {
        MobilecoreMobilecoreRow *row = [rows at:i error:error];
        if (!row) return nil;
        LLRow *metadata = [LLRow new];
        metadata.identifier = row.id_;
        metadata.revision = row.revision;
        metadata.title = row.title;
        metadata.state = row.state;
        [output addObject:metadata];
    }
    return output;
}
- (LLReceipt *)receipt:(MobilecoreMobilecoreReceipt *)value {
    if (!value) return nil;
    LLReceipt *receipt = [LLReceipt new];
    receipt.identifier = value.id_;
    receipt.revision = value.revision;
    return receipt;
}
- (LLReceipt *)createLoginWithTitle:(NSString *)title URL:(NSString *)url username:(NSData *)username password:(NSData *)password error:(NSError **)error {
    return [self receipt:[_core createLogin:title url:url username:username password:password error:error]];
}
- (LLReceipt *)generateLoginWithTitle:(NSString *)title URL:(NSString *)url username:(NSData *)username length:(NSInteger)length error:(NSError **)error {
    return [self receipt:[_core generateLogin:title url:url username:username length:length error:error]];
}
- (LLReceipt *)editID:(NSString *)identifier revision:(NSString *)revision field:(NSString *)field value:(NSData *)value error:(NSError **)error {
    return [self receipt:[_core editField:identifier revision:revision field:field value:value error:error]];
}
- (LLReceipt *)regenerateID:(NSString *)identifier revision:(NSString *)revision length:(NSInteger)length error:(NSError **)error {
    return [self receipt:[_core regeneratePassword:identifier revision:revision length:length error:error]];
}
- (LLSecretHandle *)revealID:(NSString *)identifier revision:(NSString *)revision field:(NSString *)field error:(NSError **)error {
    MobilecoreMobilecoreSecretValue *value = [field isEqualToString:@"otp-code"] ? [_core revealOTP:identifier revision:revision error:error] : [_core revealField:identifier revision:revision field:field error:error];
    if (!value) return nil;
    LLSecretHandle *handle = [LLSecretHandle new];
    handle.core = value;
    return handle;
}
- (LLStoreAdapter *)adapter:(id<LLSystemUnlockStore>)store { LLStoreAdapter *adapter = [LLStoreAdapter new]; adapter.native = store; return adapter; }
- (BOOL)enableSystemUnlock:(id<LLSystemUnlockStore>)store error:(NSError **)error { return [_core enableSystemUnlock:[self adapter:store] error:error]; }
- (BOOL)unlockWithSystem:(id<LLSystemUnlockStore>)store error:(NSError **)error { return [_core unlockWithSystem:[self adapter:store] error:error]; }
- (BOOL)disableSystemUnlock:(id<LLSystemUnlockStore>)store error:(NSError **)error { return [_core disableSystemUnlock:[self adapter:store] error:error]; }
- (NSString *)description { return @"[native vault]"; }
@end
