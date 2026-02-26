plugins {
    id("com.android.library") version "9.0.1" apply false
    id("org.jetbrains.dokka") version "2.2.0-Beta" apply false
    id("org.jetbrains.dokka-javadoc") version "2.2.0-Beta" apply false
}

tasks.register("clean", Delete::class) {
    delete(rootProject.layout.buildDirectory)
}
