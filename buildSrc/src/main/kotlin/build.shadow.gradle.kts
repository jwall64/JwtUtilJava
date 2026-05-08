import buildlogic.Utils

plugins {
    id("build.common")
    id("com.gradleup.shadow")
}

tasks {
    build {
        dependsOn(shadowJar)
    }
    shadowJar {
        configurations = listOf(project.configurations.shadow.get())
    }
}

tasks.shadowJar {
    archiveBaseName.set(Utils.getArchiveName(project))
    archiveClassifier.set("")
}

tasks.jar {
    archiveClassifier.set("partial")
}

shadow {
    addShadowVariantIntoJavaComponent = false
}
