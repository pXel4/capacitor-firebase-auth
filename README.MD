
[![npm version](https://badge.fury.io/js/capacitor-firebase-auth.svg)](https://badge.fury.io/js/capacitor-firebase-auth)

# capacitor-firebase-auth

Capacitor plugin for Firebase Authentication that handle the authentication on Native layer and propagate the token to the web view layer. After the sing in process complete the user will be signed in in both tiers.

Actually the plugins support Google, Twitter and Facebook providers in Android and iOS.

The Phone Number and Email/Password providers are in the Road Map.

> This is a working in progress plugins, as soon as we have notices that some one is using this in production without problems we will remove this disclaimer.

## What news

- Providers list in plugin configurations (braking changes - see How to Config - Capacitor Plugin Item 1)
- Dependency updates for android platform (Firebase 17 and Facebook 5)

## Old news
- Configuration for when authenticate on native layer (default false to avoid double billing)
- Fix the issue #1: Default FirebaseApp is not initialized on Android platform
- WIP: Phone verification sign in on iOS platform.
- Phone verification sign in on Android platform. 
- How to install and config on Google, Twitter and Facebook.
- Fix to work without Facebook configurations.
- Better sign out implementation.
- Better observable implementations on js facade.
- Facebook Provider authentication in iOS platform
- Facebook Provider authentication in Android platform
- Twitter Provider authentication in iOS platform
- Twitter Provider authentication in Android platform
- The Typescript facade for the plugin
- Google Provider authentication in iOS Platform
- Google Provider authentication in Android platform
- Scaffolding do plugin (npx @capacitor/cli plugin:generate)

## Next steps

1. Phone Number Provider in iOS platform
2. Email/Password Provider

### How to Install

Install the plugin into your Capacitor project with npm.

```
npm install --save capacitor-firebase-auth
```
 
### How to Config

## Capacitor Plugins

1. In file `capacitor.config.json` config the providers list and native authentication as desired
    ```
    [...]
      "plugins": {
        "CapacitorFirebaseAuth": {
          "providers": ["google.com", "twitter.com", "facebook.com", "phone"]
          "nativeAuth": false
        }
      }
    [...]
    ```


2. In file `android/app/src/main/java/br/com/petrobras/br/ma02/MainActivity.java` add the reference to the Capacitor Firebase Auth plugin inside the Bridge initialization.
    ```
    [...]
    // Initializes the Bridge
    this.init(savedInstanceState, new ArrayList<Class<? extends Plugin>>() {{
      // Additional plugins you've installed go here
      // Ex: add(TotallyAwesomePlugin.class);
      add(CapacitorFirebaseAuth.class);
    }});
    [...]
    ```
    
3. In file `android/app/build.gradle` add the following lines : 
    ```
    android {
        compileOptions {
            sourceCompatibility JavaVersion.VERSION_1_8
            targetCompatibility JavaVersion.VERSION_1_8
        }
    }
    ```
    > Sorry, but even if you are not using Twitter authentication, this will be needed, see Twitter section for detail.

## Firebase

1. Follow instructions to add Firebase to your native project:
    * [Add Firebase to your Android project](https://firebase.google.com/docs/android/setup)
    * [Add Firebase to your iOS project ](https://firebase.google.com/docs/ios/setup)
2. If you haven't yet connected your app to your Firebase project, do so from the [Firebase console](https://console.firebase.google.com/).

> Please, don't forgot your Google Service _.json_ or _.plist_ file or your app will crash on the startup.

#### Firebase iOS specific configurations

3. Add the pods that you want to install. You can include a Pod in your Podfile like this:

    ```
    target 'App' do
      capacitor_pods
      # Add your Pods here
        pod 'Firebase/Core'
        pod 'Firebase/Auth'
    end
    ```

## Google

#### Google global configurations

1. Enable Google Sign-In in the Firebase console:
    * In the [Firebase console](https://console.firebase.google.com/), open the **Auth** section.
    * On the **Sign in method** tab, enable the **Google** sign-in method and click **Save**.
     
#### Google Android specific configurations
    
1. If you haven't yet specified your app's SHA-1 fingerprint, do so from the [Settings page](https://console.firebase.google.com/project/_/settings/general/) of the Firebase console. See [Authenticating Your Client](https://developers.google.com/android/guides/client-auth) for details on how to get your app's SHA-1 fingerprint.

#### Google iOS specific configurations

1. Add custom URL schemes to your Xcode project:
    * Open your project configuration: double-click the project name in the left tree view. Select your app from the **TARGETS** section, then select the **Info** tab, and expand the **URL Types** section.
    * Click the **+** button, and add a `URL scheme` for your reversed client ID. To find this value, open the `GoogleService-Info.plist` configuration file, and look for the `REVERSED_CLIENT_ID` key. Copy the value of that key, and paste it into the **URL Schemes** box on the configuration page. Leave the other fields blank.

## Twitter

#### Twitter global configurations

1. [Register your app](https://apps.twitter.com/) as a developer application on Twitter and get your app's **API Key** and **API Secret**.
2. Enable Twitter Login:
    * In the [Firebase console](https://console.firebase.google.com/), open the **Auth** section
    * On the **Sign in method** tab, enable the **Twitter** sign-in method and specify the **App ID** and **App Secret** you got from Facebook.
    * Then, make sure your Firebase OAuth redirect URI (e.g. _my-app-12345.firebaseapp.com/__/auth/handler_) is set as your Callback URL in your app's settings page on your [Twitter app's config](https://apps.twitter.com/).

#### Twitter Android specific configurations

1. In file `android/app/src/main/res/values/ids.xml` add the following lines :
    ```xml
    <string name="twitter_consumer_key">[APP_ID]</string>
    <string name="twitter_consumer_secret">[APP_SECRET]</string>
    ```
    > Don't forget to replace `[APP_ID]` and `[APP_SECRET]` by your Twitter **App ID** and **App Secret** respectively.

2. In file `android/app/build.gradle` add the following lines : 
    ```
    android {
        compileOptions {
            sourceCompatibility JavaVersion.VERSION_1_8
            targetCompatibility JavaVersion.VERSION_1_8
        }
    }
    ```
    > Please See: [Invoke-customs are only supported starting with android 0 --min-api 26](https://stackoverflow.com/questions/49891730/invoke-customs-are-only-supported-starting-with-android-0-min-api-26) on stackoverflow.com.

#### Twitter iOS specific configurations

1. Create the file `ios/App/App/Twitter-Info.plist` and configure your `[APP_ID]` and `[APP_SECRET]`.
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>API_KEY</key>
        <string>[APP_ID]</string>
        <key>API_SECRET</key>
        <string>[APP_SECRET]</string>
    </dict>
    </plist>
    ```
2. Add custom URL schemes to your Xcode project:
    * Open your project configuration: double-click the project name in the left tree view. Select your app from the **TARGETS** section, then select the **Info** tab, and expand the **URL Types** section.
    * Click the **+** button, and add a `URL` scheme for the Callback URL of Twitter Kit for iOS. In **URL Schemes** box on the configuration page use `twitterkit-[APP_ID]`. Leave the other fields blank.

3. Dispatch the designated callback URL to Twitter Kit in your `ios/App/App/AppDelegate.swift` file. 
    ```
      func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
        // Called when the app was launched with a url. Feel free to add additional processing here,
        // but if you want the App API to support tracking app url opens, make sure to keep this call
        
        if let scheme = url.scheme {
            if scheme.starts(with: "twitterkit") {
                return TWTRTwitter.sharedInstance().application(app, open: url, options: options)
            }
        }
        
        return CAPBridge.handleOpenUrl(url, options)
      }
    ```
    
> Don't forget to replace `[APP_ID]` and `[APP_SECRET]` by your Twitter **App ID** and **App Secret** respectively.
      

## Facebook

#### Facebook global configurations

1. On the [Facebook for Developers](https://developers.facebook.com/) site, get the **App ID** and an **App Secret** for your app
2. Enable Facebook Login:
    * In the [Firebase console](https://console.firebase.google.com/), open the **Auth** section
    * On the **Sign in method** tab, enable the **Facebook** sign-in method and specify the **App ID** and **App Secret** you got from Facebook.
    * Then, make sure your **OAuth redirect URI** (e.g. _my-app-12345.firebaseapp.com/__/auth/handler_) is listed as one of your OAuth redirect URIs in your Facebook app's settings page on the  [Facebook for Developers](https://developers.facebook.com/) site in the **Product Settings** > **Facebook Login** config.

#### Facebook Android specific configurations 

1. Add the dependency for **Facebook SDK** to your app-level build.gradle file:
    ```
    implementation 'com.facebook.android:facebook-android-sdk:4.41.0'
    ```
2. In file `android/app/src/main/AndroidManifest.xml`, add the following XML elements under `<manifest><application>` :
   
   ```xml
   <meta-data android:name="com.facebook.sdk.ApplicationId"
       android:value="@string/facebook_app_id"/>
   
   <activity
       android:name="com.facebook.FacebookActivity"
       android:configChanges="keyboard|keyboardHidden|screenLayout|screenSize|orientation"
       android:label="@string/app_name" />
   
   <activity
       android:name="com.facebook.CustomTabActivity"
       android:exported="true">
       <intent-filter>
           <action android:name="android.intent.action.VIEW" />
           <category android:name="android.intent.category.DEFAULT" />
           <category android:name="android.intent.category.BROWSABLE" />
           <data android:scheme="@string/fb_login_protocol_scheme" />
       </intent-filter>
   </activity>
   ```
   
3. In file `android/app/src/main/res/values/ids.xml` add the following lines :
    ```xml
    <string name="facebook_app_id">[APP_ID]</string>
    <string name="fb_login_protocol_scheme">fb[APP_ID]://authorize</string>
    ```
    > Don't forget to replace `[APP_ID]` by your Facebook **App ID**.

#### Facebook iOS specific configurations

1. Add your your `[APP_ID]` and `[APP_NAME]` keys in the file `ios/App/App/Info.plist`.

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        [...]
        <key>FacebookAppID</key>
        <string>[APP_ID]</string>
        <key>FacebookDisplayName</key>
        <string>[APP_NAME]</string>
        [...]
    </dict>
    </plist>    
    ```

2. Add custom URL schemes to your Xcode project:
   * Open your project configuration: double-click the project name in the left tree view. Select your app from the **TARGETS** section, then select the **Info** tab, and expand the **URL Types** section.
   * Click the **+** button, and add a `URL` scheme for the Callback URL of Facebook Kit for iOS. In **URL Schemes** box on the configuration page use `fb[APP_ID]`. Leave the other fields blank.

3. Add the pods that you want to install. You can include a Pod in your Podfile like this:

    ```
    target 'App' do
      capacitor_pods
      # Add your Pods here
        pod 'Firebase/Core'
        pod 'Firebase/Auth'
        pod 'FBSDKCoreKit'
        pod 'FBSDKLoginKit'
    end
    ```

4. Dispatch the designated callback URL to Facebook Kit in your `ios/App/App/AppDelegate.swift` file.

    Facebook SDK >= 5.0.0
    ```
      func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
        // Called when the app was launched with a url. Feel free to add additional processing here,
        // but if you want the App API to support tracking app url opens, make sure to keep this call
        
        if let scheme = url.scheme, let host = url.host {
            if scheme == "fb\(String(describing: Settings.appID))" && host == "authorize" {
                return ApplicationDelegate.shared.application(app, open: url, options: options)
            }
        }
        
        return CAPBridge.handleOpenUrl(url, options)
      }
    ```

    FaceBook SDK <= 4.41.0
    ```
      func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
        // Called when the app was launched with a url. Feel free to add additional processing here,
        // but if you want the App API to support tracking app url opens, make sure to keep this call
        
        if let scheme = url.scheme, let host = url.host {
            if scheme == "fb\(String(describing: FBSDKSettings.appID()))" && host == "authorize" {
                return FBSDKApplicationDelegate.sharedInstance().application(app, open: url, options: options)
            }
        }
        
        return CAPBridge.handleOpenUrl(url, options)
      }
    ```


> Don't forget to replace `[APP_ID]` and `[APP_NAME]` by your Facebook **App ID** and **App Name** respectively.


## Usage

#### Sign in

```typescript
import {cfaSignIn} from 'capacitor-firebase-auth';

cfaSignIn('google.com').subscribe(
	user => console.log(user.displayName);
)
```

#### Sing out

```typescript
import {cfaSignOut} from 'capacitor-firebase-auth';

//[...]

cfaSignOut().subscribe()
```

## Known limitations

#### Phone Verification

The user will be **signed in** only in web layer. This limitation is due to the **verification code** only works once. So, there is no way to authenticate the user in both layers (native and web) with just one SMS Code.
