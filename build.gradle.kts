plugins {
    id("build.library")
    id("build.publish")
}

dependencies {

    api(libs.midnightcfg)
    api(libs.midnightcfg.codec.json)

}
