# Apifier consumer ProGuard rules

# Keep Cronet classes
-keep class org.chromium.net.** { *; }
-keep class com.google.android.gms.net.** { *; }

# Keep OkHttp classes
-dontwarn okhttp3.**
-dontwarn okio.**
-keep class okhttp3.** { *; }
-keep interface okhttp3.** { *; }

# Keep public API
-keep public class com.androidacy.apifier.** {
    public protected *;
}
