plugins { id("com.android.application"); kotlin("android") }
val coreAar = file(providers.environmentVariable("LOCKLARK_MOBILE_AAR").orElse("../../core/build/mobilecore.aar").get())
android {
    namespace = "org.locklark.android"
    compileSdk = 36
    defaultConfig {
        applicationId = "org.locklark.android"
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_21; targetCompatibility = JavaVersion.VERSION_21 }
    buildTypes { release { isMinifyEnabled = false } }
    sourceSets.getByName("androidTest").java.srcDir("../testsupport/src/main/kotlin")
}
kotlin { jvmToolchain(21) }
dependencies {
    implementation(project(":policy"))
    implementation(files(coreAar))
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:core:1.6.1")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.3.0")
}
tasks.matching { it.name == "preBuild" }.configureEach {
    doFirst { check(coreAar.isFile) { "Build the real Go mobilecore AAR first; no fallback implementation is provided." } }
}
