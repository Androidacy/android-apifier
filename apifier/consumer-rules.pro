# Apifier consumer ProGuard rules

# Cronet loads implementation classes reflectively and registers JNI symbols.
-keep class org.chromium.net.** { *; }
-keep class com.google.android.gms.net.** { *; }

# Public API surface for library consumers.
-keep public class com.androidacy.apifier.** { public protected *; }

-dontwarn okio.**
