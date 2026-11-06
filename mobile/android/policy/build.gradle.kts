plugins { kotlin("jvm") }
kotlin {
    jvmToolchain(21)
    sourceSets.getByName("test").kotlin.srcDir("../testsupport/src/main/kotlin")
}
dependencies { testImplementation("junit:junit:4.13.2") }
