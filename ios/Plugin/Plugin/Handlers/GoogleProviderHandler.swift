import Foundation
import Capacitor
import FirebaseCore
import FirebaseAuth
import GoogleSignIn

class GoogleProviderHandler: NSObject, ProviderHandler, GIDSignInDelegate, GIDSignInUIDelegate {

    var plugin: CapacitorFirebaseAuth? = nil
    
    func initialize(plugin: CapacitorFirebaseAuth) {
        print("Initializing Google Provider Handler")
        
        self.plugin = plugin
        
        GIDSignIn.sharedInstance().clientID = FirebaseApp.app()?.options.clientID
        GIDSignIn.sharedInstance().delegate = self
        GIDSignIn.sharedInstance().uiDelegate = self
        
        NotificationCenter.default
            .addObserver(self, selector: #selector(handleOpenUrl(_ :)), name: Notification.Name(CAPNotifications.URLOpen.name()), object: nil)
    }
    
    @objc
    func handleOpenUrl(_ notification: Notification) {
        guard let object = notification.object as? JSObject else {
            print("There is no object on handleOpenUrl")
            return
        }
        
        guard let url = object["url"] as? URL else {
            print("There is no url on handleOpenUrl")
            return
        }
        
        guard let options = object["options"] as? [UIApplication.OpenURLOptionsKey : Any] else {
            print("There is no options on handleOpenUrl")
            return
        }
        
        GIDSignIn.sharedInstance().handle(url, sourceApplication: options[UIApplication.OpenURLOptionsKey.sourceApplication] as? String, annotation: [:])
    }
    
    func sign(_ signIn: GIDSignIn!, present presentViewController: UIViewController) {
        DispatchQueue.main.async {
            self.plugin?.bridge.viewController.present(presentViewController, animated: true, completion: nil)
        }
    }
    
    func sign(_ signIn: GIDSignIn!, dismiss dismissViewController: UIViewController) {
        DispatchQueue.main.async {
            dismissViewController.dismiss(animated: true, completion: nil)
        }
    }
    
    func sign(_ signIn: GIDSignIn!, didSignInFor user: GIDGoogleUser!, withError error: Error!) {
        if let error = error {
            print(error.localizedDescription)
            return
        }
        
        guard let authentication = user.authentication else {
            print("There is no authentication on GIDGoogleUser")
            return
        }
        
        let credential = GoogleAuthProvider.credential(withIDToken: authentication.idToken, accessToken: authentication.accessToken)
        self.plugin?.handleAuthCredentials(credential: credential);
    }
    
    func sign(_ signIn: GIDSignIn!, didDisconnectWith user: GIDGoogleUser!, withError error: Error!) {
        self.signOut()
    }
    
    func signIn(call: CAPPluginCall) {
        GIDSignIn.sharedInstance()?.signIn();
    }
    
    func isAuthenticated() -> Bool {
        return GIDSignIn.sharedInstance()?.currentUser != nil
    }
    
    func fillResult(data: PluginResultData) -> PluginResultData {
        guard let currentUser = GIDSignIn.sharedInstance()?.currentUser else {
            return data
        }
        
        var jsResult: PluginResultData = [:]
        data.map { (key, value) in
            jsResult[key] = value
        }
    
        jsResult["idToken"] = currentUser.authentication.idToken
    
        return jsResult
    }
    
    func signOut(){
        GIDSignIn.sharedInstance()?.signOut()
    }
}
