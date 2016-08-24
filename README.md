# password_manager
<p>A cryptographically secure password manager written in Rust.</p>

<p>Create keychain with initial password by calling Keychain::init(password),
or load one by calling Keychain::load(password, json_keychain_representation).</p>
<p>Add new password with keychain.set(domain, password)</p>
<p>Retrieve saved password with keychain.get(domain)</p>
<p>Remove with keychain.remove(domain)</p>

<p>See main.rs for example usage.</p>

<h3>What's happening here?</h3>
<p>A master password is read once and then fed into PBKDF2. This secure key is used to create other secure keys for each (domain, password) being stored. The password is encrypted under AES GCM, while the domain, combined with a salt, is Sha256-hashed.</p>
