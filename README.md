# reCAPTCHA Password Check

Java client library for reCAPTCHA's
[private password check API](https://cloud.google.com/recaptcha-enterprise/docs/check-passwords).
It exposes functionality to make password leak check requests in a private
manner (i.e credentials are sent encrypted and the server cannot—and doesn't
need to—decrypt them).

## Usage

1.  Create a verifier instance:

    ```java
    PasswordCheckVerifier passwordLeak = new PasswordCheckVerifier();
    ```

2.  Create a verification with some user credentials and extract the parameters
    generated

    ```java
    PasswordCheckVerification verification = passwordLeak.createPasswordCheckVerification(username, password).get();

    byte[] lookupHashPrefix = verification.getLookupHashPrefix();
    byte[] encryptedUserCredentialsHash = verification.getEncryptedUserCredentialsHash();
    ```

3.  Next, use the parameters generated to include in your reCAPTCHA
    [assessment request](https://cloud.google.com/recaptcha-enterprise/docs/create-assessment)

4.  Then, extract the `reEncryptedUserCredentialsHash` and
    `encryptedLeakMatchPrefixes` from the response of the assessment request and
    use them to verify them:

    ```java
    PasswordCheckResult result = passwordLeak.verify(verification, reEncryptedUserCredentialsHash, encryptedLeakMatchPrefixes);
    ```

5.  Finally, use the result to determine wheter the user credentials are leaked
    or not:

    ```java
    boolean leaked = result.areCredentialsLeaked();
    ```

## Example

The following example assumes non-blocking execution (recommended for
asynchronous services) using a generic reCAPTCHA client.

```java
// Generic reCAPTCHA client
RecaptchaCustomClient reCaptchaCustomClient = createCustomClient();
PasswordCheckVerifier passwordLeakVerifier = new PasswordCheckVerifier();

CompletableFuture<PasswordCheckVerification> verificationFuture =
  passwordLeakVerifier.createPasswordCheckVerification(username, password);

CompletableFuture<PasswordCheckResult> = verificationFuture
  // Create an assessment using the parameters generated by the verifier
  .thenCompose(verification -> {
    CustomAssessment assessment = createAssessment();
    CustomPasswordCheckRequest request = createPasswordCheckRequest();
    request.setLookupHashPrefix(verification.getLookupHashPrefix());
    request.setEncryptedLookupHash(
            verification.getEncryptedUserCredentialsHash());
    assessment.setPasswordCheckRequest(lookup);

    // Assuming that the reCAPTCHA client returns a CompletableFuture
    return reCaptchaCustomClient.createAssessment(assessment);
  })
  // Verify the result of the assessemnt and builds a PasswordCheckResult
  .thenCompose(result ->
    passwordLeakVerifier.verify(verification, result.getReEncryptedUserCredentials(), result.getEncryptedLeakMatchPrefixes());
  )
  // Detemine if the credentials are leaked or not
  .thenApply(result ->
    System.out.println("Credentials are leaked? " + result.areCredentialsLeaked());
  );
```
