# Apifier consumer ProGuard rules

# Cronet loads implementation classes reflectively and registers JNI symbols.
-keep class org.chromium.net.** { *; }
-keep class com.google.android.gms.net.** { *; }

# Public API surface for library consumers.
-keep public class com.androidacy.apifier.** { public protected *; }

-dontwarn okio.**

# DataStoreCookieStorage is kept by the rule above and compiled against androidx.datastore, which
# is compileOnly. A consumer that does not depend on DataStore has no such classes for R8 to
# resolve, and full mode treats the missing references as errors.
-dontwarn androidx.datastore.**
