plugins {
    id("com.android.library")
    id("org.jetbrains.dokka")
    id("org.jetbrains.dokka-javadoc")
    `maven-publish`
}

android {
    namespace = "com.androidacy.apifier"
    compileSdk = 37
    compileSdkMinor = 0

    defaultConfig {
        minSdk = 26

        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        jvmToolchain(17)
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
        // Robolectric installs Conscrypt as a JVM-wide security provider, which then serves
        // SSLContext.getInstance("TLS") for every later test class in the same JVM. Its
        // server-side handshake needs reflective access into java.net that this JDK denies,
        // so TrustedResolverTest's local TLS servers would fail depending on class order.
        // One JVM per class keeps that leak contained.
        unitTests.all { it.setForkEvery(1) }
    }
}

dependencies {
    // Okio, used directly by the com.androidacy.apifier.http types (RequestBody.writeTo,
    // ResponseBody.source)
    api("com.squareup.okio:okio:3.18.1")

    // Cronet
    api("com.google.android.gms:play-services-cronet:18.1.1")
    api("org.chromium.net:cronet:500.0.1")
    implementation("org.chromium.net:cronet-bundled:500.0.1")

    // Kotlin coroutines
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")

    // AndroidX
    implementation("androidx.core:core-ktx:1.19.0")

    // DataStore: only needed by consumers using DataStoreCookieStorage
    compileOnly("androidx.datastore:datastore-preferences:1.2.1")

    // Tests
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.16.1")
    testImplementation("androidx.test:core:1.7.0")
}

val dokkaJavadocJar by tasks.registering(Jar::class) {
    from(tasks.dokkaGeneratePublicationJavadoc.flatMap { it.outputDirectory })
    archiveClassifier.set("javadoc")
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                artifact(dokkaJavadocJar)
                groupId = "com.github.Androidacy"
                artifactId = "android-apifier"
                version = "3.0.0"

                pom {
                    name.set("Android Apifier")
                    description.set("Cronet-native HTTP and API networking library for Android")
                    url.set("https://github.com/Androidacy/android-apifier")
                    licenses {
                        license {
                            name.set("The Apache License, Version 2.0")
                            url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                        }
                    }
                }
            }
        }
    }
}
