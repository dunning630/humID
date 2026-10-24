plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "app.humid.docscan"
    compileSdk = 37

    defaultConfig {
        minSdk = 37 // Android 17 (HumID 5.0 floor)
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-ktx:1.9.3")
    // The scanner's screens and models come from Google Play services, on the phone.
    implementation("com.google.android.gms:play-services-mlkit-document-scanner:16.0.0")
    implementation(project(":tauri-android"))
}
