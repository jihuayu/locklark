#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@protocol LLSystemUnlockStore <NSObject>
- (BOOL)storeID:(NSString *)identifier data:(NSData *)data error:(NSError **)error NS_SWIFT_NAME(store(id:value:));
- (nullable NSData *)loadID:(NSString *)identifier error:(NSError **)error NS_SWIFT_NAME(load(id:));
- (BOOL)deleteID:(NSString *)identifier error:(NSError **)error NS_SWIFT_NAME(delete(id:));
@end

@interface LLRow : NSObject
@property(nonatomic, readonly) NSString *identifier;
@property(nonatomic, readonly) NSString *revision;
@property(nonatomic, readonly) NSString *title;
@property(nonatomic, readonly) NSString *state;
@end

@interface LLReceipt : NSObject
@property(nonatomic, readonly) NSString *identifier;
@property(nonatomic, readonly) NSString *revision;
@end

@interface LLDisclosure : NSObject
@property(nonatomic, readonly) NSMutableData *data;
@property(nonatomic, readonly) int64_t fromUnixMilli;
@property(nonatomic, readonly) int64_t untilUnixMilli;
- (void)clear;
@end

@interface LLSecretHandle : NSObject
- (nullable LLDisclosure *)takeAndReturnError:(NSError **)error NS_SWIFT_NAME(take());
- (void)clear;
@end

@interface LLVault : NSObject
+ (nullable instancetype)openAtPath:(NSString *)path error:(NSError **)error NS_SWIFT_NAME(open(path:));
+ (nullable NSData *)generateSecretKeyAndReturnError:(NSError **)error NS_SWIFT_NAME(generateSecretKey());
+ (NSString *)formatSecretKey:(NSData *)key;
+ (nullable NSData *)parseSecretKey:(NSString *)text error:(NSError **)error NS_SWIFT_NAME(parseSecretKey(_:));
- (BOOL)createWithPassword:(NSData *)password secretKey:(NSData *)key error:(NSError **)error NS_SWIFT_NAME(create(password:secretKey:));
- (BOOL)unlockWithPassword:(NSData *)password secretKey:(NSData *)key error:(NSError **)error NS_SWIFT_NAME(unlock(password:secretKey:));
- (BOOL)isUnlocked NS_SWIFT_NAME(isUnlocked());
- (void)requestLock;
- (void)lock;
- (void)close;
- (nullable NSArray<LLRow *> *)rowsForQuery:(NSString *)query error:(NSError **)error NS_SWIFT_NAME(rows(query:));
- (nullable LLReceipt *)createLoginWithTitle:(NSString *)title URL:(NSString *)url username:(NSData *)username password:(NSData *)password error:(NSError **)error NS_SWIFT_NAME(createLogin(title:url:username:password:));
- (nullable LLReceipt *)generateLoginWithTitle:(NSString *)title URL:(NSString *)url username:(NSData *)username length:(NSInteger)length error:(NSError **)error NS_SWIFT_NAME(generateLogin(title:url:username:length:));
- (nullable LLReceipt *)editID:(NSString *)identifier revision:(NSString *)revision field:(NSString *)field value:(NSData *)value error:(NSError **)error NS_SWIFT_NAME(edit(id:revision:field:value:));
- (nullable LLReceipt *)regenerateID:(NSString *)identifier revision:(NSString *)revision length:(NSInteger)length error:(NSError **)error NS_SWIFT_NAME(regenerate(id:revision:length:));
- (nullable LLSecretHandle *)revealID:(NSString *)identifier revision:(NSString *)revision field:(NSString *)field error:(NSError **)error NS_SWIFT_NAME(reveal(id:revision:field:));
- (BOOL)enableSystemUnlock:(id<LLSystemUnlockStore>)store error:(NSError **)error NS_SWIFT_NAME(enableSystemUnlock(_:));
- (BOOL)unlockWithSystem:(id<LLSystemUnlockStore>)store error:(NSError **)error NS_SWIFT_NAME(unlockWithSystem(_:));
- (BOOL)disableSystemUnlock:(id<LLSystemUnlockStore>)store error:(NSError **)error NS_SWIFT_NAME(disableSystemUnlock(_:));
@end

NS_ASSUME_NONNULL_END
