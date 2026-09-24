plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }

android {
    namespace = "com.mpcallsecurity"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.mpcallsecurity"
        minSdk = 26
        targetSdk = 35
        versionCode = 3
        versionName = "1.2.0"
    }
    signingConfigs {
        create("release") {
            val storeFilePath = System.getenv("ANDROID_KEYSTORE_PATH")
            if (!storeFilePath.isNullOrBlank()) {
                storeFile = file(storeFilePath)
                storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("ANDROID_KEY_PASSWORD")
            }
        }
    }
    buildTypes {
        release {
            val hasSigning = !System.getenv("ANDROID_KEYSTORE_PATH").isNullOrBlank()
            if (hasSigning) signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = false
        }
    }
}
