### Overview

This repo has some code that performs encryption of data using Hashicorp's Vault for key management (including creation of the keys), in particular, uses datakey from Transite Engine. First I show some examples with vault's command line to show the principles of the approach, and then I explain how to setup the environment to run the script. The script itself reads files in chunks, then each chunk is first encrytpted and then uploaded to its destination, in this case an Azure Stroage container. 

### Prerequisites

- A running instance of Vault, initialized and unsealed.
- Your VAULT_ADDR & VAULT_TOKEN variables set in your shell (or any other mechanism you prefer to interact with vault).
- If you want to see the upload funcionality of the python script in action: Connection String of an Azure Storage account with a container created. 
- Vault binaries downloaded to run cli commands. 

### How it Works?

Let's cover the Vault component first, we need to setup a couple of things. 

##### Transit Engine

To enable transit engine
```bash
> vault secrets enable transit 
```

##### Create Key

Now, lets create a key, I am giving it the name: `calabaza` and we need it to be `AES-GCM` with `256 bits` key and `96 bits` nonce. Vault will create a new randomly generated key with the specified cipher.
```bash
> vault write -f transit/keys/calabaza type=aes256-gcm96 
```


Check that your key has been created

```bash
> vault list transit/keys

Keys
----
calabaza
```

##### Ask Vault to encrypt/decrypt data

At this point Vault has created a key, there are a lot if things that Vault can do at this point, you can encrypt/decrypt/rewrap/sign/verify data, you can apply policies and access control, rotate it, delete it. All of that without even knowing the content of the key. Let's try:

> Note: All the data that you send and receive from Vault has to be base64 encoded, this allows easier manipulation of text and binary data. 

Encrypting:
```bash
> vault write transit/encrypt/calabaza plaintext=$(echo "My Data" | base64)

Key           Value
---           -----
ciphertext    vault:v1:X9NeufU6AhOqZTStkz3ohkTvdPKa4TBTqLMRGANXwW2njbKC
```

Decrypting (Sending the value that you got from the previous command):
```bash
> vault write transit/decrypt/calabaza ciphertext='vault:v1:X9NeufU6AhOqZTStkz3ohkTvdPKa4TBTqLMRGANXwW2njbKC'

Key          Value
---          -----
plaintext    TXkgRGF0YQ==

# Since its base64 encoded, lets just add some pipe magic to include decoding

> vault write transit/decrypt/calabaza ciphertext='vault:v1:X9NeufU6AhOqZTStkz3ohkTvdPKa4TBTqLMRGANXwW2njbKC' -format=json | jq -r '.data.plaintext' | base64 -d

My Data
```

##### Ask Vault for a DataKey and encrypt data yourself

In the previous section Vault is the one performing the encryption operation, all you have to do is send all the data un-encrypted and then just wait for it to come back encrypted and nothing ever gets stored in Vault. 

Now, what happens if we need to encrypt A LOT of data, or if you want to perform extremely fast encryption using specialized hardware or any other similar use case. We can do that by asking Vault to generate as many keys as we want and have them wrapped by a previously created transit key. Lets try:

Create a new random key and get it both: `Wrapped` (encrypted) and `Base64 Encoded` (decrypted)
```bash
# Every time you run this command you will get a NEW key
> vault write -f /transit/datakey/plaintext/calabaza

Key           Value
---           -----
ciphertext    vault:v1:zWn3WjMYLZ7oL5eYwmNp1Rj3yHIQdkjCgaYk/Dw6HzKgBsrbzV0h+kcm+RnS7NLjuIBbwGd4mMiyyszB
plaintext     J/bDCb4ibqleFYExo9XoTdLhsTP3gwTvsxrS2yt6b7E=

```

Now, the `plaintext` value is the key itself (base64 encoded), ready to be used with your favorite encryption tool. Lets try it with openssl, which can take a key in hex format:

> Keep note of the ciphertext!!!

First, let's get the hex representation of the key
```bash
> echo -n "J/bDCb4ibqleFYExo9XoTdLhsTP3gwTvsxrS2yt6b7E=" | base64 -d | xxd -p -c 32

27f6c309be226ea95e158131a3d5e84dd2e1b133f78304efb31ad2db2b7a6fb1
```
> Explaining the parameters: 
>
>[echo] 
-n To remove the newline from the echo command
 [base64] 
-d To specify that we want to decode
[xdd]
-p To print the hex value in plain format
-c Number of colums before xxd adds a newline  (we know our key is 256 bits == 32 bytes)

Next, let's create a simple text file:
```bash
> echo "Super secret information" > file.txt
```

Now, encrypt it with `openssl enc`

```bash
> openssl enc -aes-256-gcm -K 27f6c309be226ea95e158131a3d5e84dd2e1b133f78304efb31ad2db2b7a6fb1 -iv 000000000000000000000000 -in file.txt -out file.enc
```

> Parameters: 
>
> -aes-256-gcm Here we specify the cipher (same as the one we requested a key for)
> -K To specify the key, as mentioned, it must be in hex format
> -iv The initialization Vector required by the cipher, also in hex format
> -in The source file
> -out Where the encrypted data will be written into
>
> Both the Key and the IV are required by the entity that will decrypt the information. A very strict cryptographic requirement is that the combination of Key and IV **should never** be used more than once. IV is not considered a secret.

This will give me an encrypted file `file.enc` that I can safely transport wherever I want along with its **encrypted** key, and make sure I throw away the un-encrypted key,  by doing this, the only way to get to the key again will be by asking for it to Vault. Let's see how:
> The value of our encrypted key is this: `vault:v1:zWn3WjMYLZ7oL5eYwmNp1Rj3yHIQdkjCgaYk/Dw6HzKgBsrbzV0h+kcm+RnS7NLjuIBbwGd4mMiyyszB`

Unwrap the key:
```bash
> vault write transit/decrypt/calabaza ciphertext='vault:v1:zWn3WjMYLZ7oL5eYwmNp1Rj3yHIQdkjCgaYk/Dw6HzKgBsrbzV0h+kcm+RnS7NLjuIBbwGd4mMiyyszB'

Key          Value
---          -----
plaintext    J/bDCb4ibqleFYExo9XoTdLhsTP3gwTvsxrS2yt6b7E=
```

You might recognize this value, its the exact same key we got when we asked Vault for the datakey. This key was never stored in Vault, instead, it was just wrapped and given to us. 

As you can see, all the operations performed in Vault use completetly different endpoints meaning that the access control can be very granular to even the point of having 3 personas with only access to a single task each:

1. The Key Provider: Only able to request datakeys
2. The Encryptor: Only able to encrypt data for a specific key
3. The Decryptor: Only able to decrypt data for a specific key


Ahhh, in case you want to test the decryption of the file this is the command, but technically you would do this in a different place or even using another tool, as long as you specify the same cipher and the other params:


```bash
> openssl enc -aes-256-gcm -K 27f6c309be226ea95e158131a3d5e84dd2e1b133f78304efb31ad2db2b7a6fb1 -iv 000000000000000000000000 -d -in file.enc -out file_back.txt
```

> Only new Parameter:
> -d To perform decrypt operation
