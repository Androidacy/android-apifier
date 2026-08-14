plugins {
    id("com.android.library") version "9.3.1" apply false
    id("org.jetbrains.dokka") version "2.2.0" apply false
    id("org.jetbrains.dokka-javadoc") version "2.2.0" apply false
}

tasks.register("clean", Delete::class) {
    delete(rootProject.layout.buildDirectory)
}
