package com.baumblatt.capacitor.firebase.auth.handlers;

import android.content.Intent;
import android.support.annotation.NonNull;
import android.util.Log;

import com.baumblatt.capacitor.firebase.auth.CapacitorFirebaseAuth;
import com.baumblatt.capacitor.firebase.auth.R;
import com.getcapacitor.JSObject;
import com.getcapacitor.PluginCall;
import com.google.android.gms.auth.api.signin.GoogleSignIn;
import com.google.android.gms.auth.api.signin.GoogleSignInAccount;
import com.google.android.gms.auth.api.signin.GoogleSignInClient;
import com.google.android.gms.auth.api.signin.GoogleSignInOptions;
import com.google.android.gms.auth.api.signin.GoogleSignInStatusCodes;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.auth.AuthCredential;
import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.auth.GoogleAuthProvider;

public class GoogleProviderHandler implements ProviderHandler, GoogleApiClient.OnConnectionFailedListener {
    public static final int RC_GOOGLE_SIGN_IN = 9001;
    private static final String GOOGLE_TAG = "GoogleProviderHandler";

    private CapacitorFirebaseAuth plugin;
    private GoogleSignInClient mGoogleSignInClient;

    @Override
    public void init(CapacitorFirebaseAuth plugin) {
        this.plugin = plugin;

        GoogleApiAvailability googleAPI = GoogleApiAvailability.getInstance();
        int result = googleAPI.isGooglePlayServicesAvailable(this.plugin.getContext());
        if (result == ConnectionResult.SUCCESS) {
            Log.d(GOOGLE_TAG, "Google Api is Available.");
        } else {
            Log.w(GOOGLE_TAG, "Google Api is not Available.");
        }

        GoogleSignInOptions gso = new GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
                .requestIdToken(this.plugin.getContext().getString(R.string.default_web_client_id))
                .requestEmail()
                .build();

        this.mGoogleSignInClient = GoogleSignIn.getClient(this.plugin.getActivity(), gso);
    }

    @Override
    public void signIn(PluginCall call) {
        Log.d(GOOGLE_TAG, "Google SignIn starts..");
        Intent intent = this.mGoogleSignInClient.getSignInIntent();
        this.plugin.startActivityForResult(call, intent, RC_GOOGLE_SIGN_IN);
    }

    @Override
    public int getRequestCode() {
        return RC_GOOGLE_SIGN_IN;
    }

    @Override
    public void handleOnActivityResult(int requestCode, int resultCode, Intent data) {
        Log.d(GOOGLE_TAG, "Google SignIn activity result.");

        try {
            Task<GoogleSignInAccount> task = GoogleSignIn.getSignedInAccountFromIntent(data);
            // Google Sign In was successful, authenticate with Firebase
            GoogleSignInAccount account = task.getResult(ApiException.class);

            if(account != null) {
                Log.d(GOOGLE_TAG, "Google Sign In succeed.");
                AuthCredential credential = GoogleAuthProvider.getCredential(account.getIdToken(), null);
                this.plugin.handleAuthCredentials(credential);
                return;
            }
        } catch (ApiException exception) {
            // Google Sign In failed, update UI appropriately
            Log.w(GOOGLE_TAG, GoogleSignInStatusCodes.getStatusCodeString(exception.getStatusCode()), exception);
            plugin.handleFailure("Google Sign In failure.", exception);
            return;
        }

        plugin.handleFailure("Google Sign In failure.", null);
    }

    @Override
    public boolean isAuthenticated() {
        GoogleSignInAccount account = GoogleSignIn.getLastSignedInAccount(this.plugin.getContext());
        return account != null;
    }

    @Override
    public void fillResult(JSObject jsResult) {
        GoogleSignInAccount account = GoogleSignIn.getLastSignedInAccount(this.plugin.getContext());
        jsResult.put("idToken", account.getIdToken());
    }

    @Override
    public void signOut() {
        this.mGoogleSignInClient.signOut().addOnCompleteListener(this.plugin.getActivity(), new OnCompleteListener<Void>() {
            @Override
            public void onComplete(@NonNull Task<Void> task) {
                Log.i(GOOGLE_TAG, "Google Sign Out succeed.");
            }
        });
    }

    @Override
    public void onConnectionFailed(@NonNull ConnectionResult connectionResult) {
        Log.i(GOOGLE_TAG, "Unresolvable failure in connecting to Google APIs");
    }
}
