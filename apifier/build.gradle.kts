plugins {
    id("com.android.library")
    id("org.jetbrains.dokka")
    id("org.jetbrains.dokka-javadoc")
    `maven-publish`
}

android {
    namespace = "com.androidacy.apifier"
    compileSdk = 36

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
}

dependencies {
    // OkHttp
    api("com.squareup.okhttp3:okhttp:5.3.0")

    // Cronet
    api("com.google.android.gms:play-services-cronet:18.1.1")
    api("org.chromium.net:cronet-api:143.7445.0")
    implementation("org.chromium.net:cronet-embedded:143.7445.0")

    // Kotlin coroutines
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    api("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")

    // AndroidX
    implementation("androidx.core:core-ktx:1.17.0")

    // DataStore (optional — only needed if using DataStoreCookieStorage)
    compileOnly("androidx.datastore:datastore-preferences:1.2.0")
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
                version = "1.4.1"

                pom {
                    name.set("Android Apifier")
                    description.set("HTTP and API networking library for Android with Cronet and OkHttp")
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
