#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@protocol PMSystemUnlockStore <NSObject>
- (BOOL)storeID:(NSString *)identifier data:(NSData *)data error:(NSError **)error NS_SWIFT_NAME(store(id:value:));
- (nullable NSData *)loadID:(NSString *)identifier error:(NSError **)error NS_SWIFT_NAME(load(id:));
- (BOOL)deleteID:(NSString *)identifier error:(NSError **)error NS_SWIFT_NAME(delete(id:));
@end

@interface PMRow : NSObject
@property(nonatomic, readonly) NSString *identifier;
@property(nonatomic, readonly) NSString *revision;
@property(nonatomic, readonly) NSString *title;
@property(nonatomic, readonly) NSString *state;
@end

@interface PMReceipt : NSObject
@property(nonatomic, readonly) NSString *identifier;
@property(nonatomic, readonly) NSString *revision;
@end

@interface PMDisclosure : NSObject
@property(nonatomic, readonly) NSMutableData *data;
@property(nonatomic, readonly) int64_t fromUnixMilli;
@property(nonatomic, readonly) int64_t untilUnixMilli;
- (void)clear;
@end

@interface PMSecretHandle : NSObject
- (nullable PMDisclosure *)takeAndReturnError:(NSError **)error NS_SWIFT_NAME(take());
- (void)clear;
@end

@interface PMVault : NSObject
+ (nullable instancetype)openAtPath:(NSString *)path error:(NSError **)error NS_SWIFT_NAME(open(path:));
+ (nullable NSData *)generateSecretKeyAndReturnError:(NSError **)error NS_SWIFT_NAME(generateSecretKey());
+ (NSString *)formatSecretKey:(NSData *)key;
+ (nullable NSData *)parseSecretKey:(NSString *)text error:(NSError **)error NS_SWIFT_NAME(parseSecretKey(_:));
- (nullable PMVault *)captureOperationAndReturnError:(NSError **)error NS_SWIFT_NAME(captureOperation());
- (BOOL)createWithPassword:(NSData *)password secretKey:(NSData *)key error:(NSError **)error NS_SWIFT_NAME(create(password:secretKey:));
- (BOOL)unlockWithPassword:(NSData *)password secretKey:(NSData *)key error:(NSError **)error NS_SWIFT_NAME(unlock(password:secretKey:));
- (BOOL)isUnlocked NS_SWIFT_NAME(isUnlocked());
- (void)requestLock;
- (void)lock;
- (void)close;
- (nullable NSArray<PMRow *> *)rowsForQuery:(NSString *)query error:(NSError **)error NS_SWIFT_NAME(rows(query:));
- (nullable PMReceipt *)createLoginWithTitle:(NSString *)title URL:(NSString *)url username:(NSData *)username password:(NSData *)password error:(NSError **)error NS_SWIFT_NAME(createLogin(title:url:username:password:));
- (nullable PMReceipt *)generateLoginWithTitle:(NSString *)title URL:(NSString *)url username:(NSData *)username length:(NSInteger)length error:(NSError **)error NS_SWIFT_NAME(generateLogin(title:url:username:length:));
- (nullable PMReceipt *)editID:(NSString *)identifier revision:(NSString *)revision field:(NSString *)field value:(NSData *)value error:(NSError **)error NS_SWIFT_NAME(edit(id:revision:field:value:));
- (nullable PMReceipt *)regenerateID:(NSString *)identifier revision:(NSString *)revision length:(NSInteger)length error:(NSError **)error NS_SWIFT_NAME(regenerate(id:revision:length:));
- (nullable PMSecretHandle *)revealID:(NSString *)identifier revision:(NSString *)revision field:(NSString *)field error:(NSError **)error NS_SWIFT_NAME(reveal(id:revision:field:));
- (BOOL)enableSystemUnlock:(id<PMSystemUnlockStore>)store error:(NSError **)error NS_SWIFT_NAME(enableSystemUnlock(_:));
- (BOOL)unlockWithSystem:(id<PMSystemUnlockStore>)store error:(NSError **)error NS_SWIFT_NAME(unlockWithSystem(_:));
- (BOOL)disableSystemUnlock:(id<PMSystemUnlockStore>)store error:(NSError **)error NS_SWIFT_NAME(disableSystemUnlock(_:));
@end

NS_ASSUME_NONNULL_END
