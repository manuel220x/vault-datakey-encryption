#!/usr/bin/env python

from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES

from enum import Enum

import os
import struct
import hvac
import uuid
from base64 import b64decode
import binascii
import time
from azure.storage.blob import BlobBlock, BlobServiceClient
from cryptography.exceptions import InvalidTag
import sys

class KeySource(Enum):
    LOCAL = 1
    HASHI_VAULT = 2

class BufferWritter(Enum):
    LOCAL = 1
    AZURE = 2


class BufferedAESGCM:
    
    STRUCT_FORMAT = "=H{len_kct}sH{len_iv}s"

    def __init__(self, key_source=KeySource.LOCAL, key = None, iv=None, key_ciphertext=None):
        self.cipher = None
        self.vault = None
        self._key_source = key_source

        if key_source == KeySource.LOCAL:
            if key is not None and key_ciphertext is None:
                raise Exception ("When using local key mode, 'key_ciphertext' parameter must be provided")

        self._param_key = key
        self._param_iv = iv
        self._param_key_ciphertext = key_ciphertext

    def init_cipher(self):
        if self.cipher is None:
            self.cipher = ciphers.Cipher(AES(self._key), modes.GCM(self._iv))

    def _init_cipher_params(self, key=None, iv=None, key_ciphertext=None, new_key=True):
        if key is not None:
            if self._key_source == KeySource.LOCAL:
                self._key = key
            elif self._key_source == KeySource.HASHI_VAULT and new_key:
                self._vault_init()
                self._key, self._key_ciphertext = self._vault_get_datakey(key)
            elif self._key_source == KeySource.HASHI_VAULT and not new_key:
                self._vault_init()
                self._key = self._vault_unwrap_datakey(key,key_ciphertext)
        
        if iv is not None:
            self._iv = iv

        if key_ciphertext is not None:
            self._key_ciphertext = key_ciphertext

    def _vault_init(self):
        if self.vault is not None:
            return
        if 'VAULT_ADDR' not in os.environ:
            raise Exception("VAULT_ADDR environment variable not set")
        if 'APP_ROLE_ID' not in os.environ:
            raise Exception("APP_ROLE_ID environment variable not set")
        if 'APP_SECRET_ID' not in os.environ:
            raise Exception("APP_SECRET_ID environment variable not set")
        
        self.vault = hvac.Client(url=os.environ.get('VAULT_ADDR'))
        self.vault.auth_approle(os.environ.get('APP_ROLE_ID'), os.environ.get('APP_SECRET_ID'))
        
        if not self.vault.is_authenticated():
            raise Exception("Authentication Failed")
    
    def _vault_unwrap_datakey(self,name, ciphertext):
        vault_response = self.vault.secrets.transit.decrypt_data(
            name=name,
            ciphertext=ciphertext)
        return b64decode(vault_response['data']['plaintext'])
    
    def _vault_get_datakey(self,name):
        vault_response = self.vault.secrets.transit.generate_data_key(
            name=name,
            key_type='plaintext')
        return b64decode(vault_response['data']['plaintext']),vault_response['data']['ciphertext']

    def build_headers(self):
        struct_format = self.STRUCT_FORMAT.format(len_kct=len(self._key_ciphertext),len_iv=len(self._iv))
        encryption_header = struct.pack(struct_format,
            len(self._key_ciphertext), self._key_ciphertext.encode('utf-8'),
            len(self._iv), self._iv
        )
        return encryption_header

    def parse_headers(self,encrypted_file_stream):
        size_ct = struct.unpack("H", encrypted_file_stream.read(2))[0]
        ct_str = struct.unpack(str(size_ct)+"s", encrypted_file_stream.read(size_ct))[0]
        size_iv = struct.unpack("H", encrypted_file_stream.read(2))[0]
        iv_str = struct.unpack(str(size_iv)+"s", encrypted_file_stream.read(size_iv))[0]
        # Now lets get the key from Vault
        self._init_cipher_params(self._param_key, iv_str, ct_str.decode(), new_key=False)
        #
        struct_format = self.STRUCT_FORMAT.format(len_kct=len(self._key_ciphertext),len_iv=len(self._iv))
        return struct.calcsize(struct_format)
    
    def parse_blob_headers(self,blob_client):
        blob_stream = blob_client.download_blob(offset=0, length=2)
        size_ct = struct.unpack("H", blob_stream.content_as_bytes())[0]
        blob_stream = blob_client.download_blob(offset=2, length=size_ct)
        ct_str = struct.unpack(str(size_ct)+"s", blob_stream.content_as_bytes())[0]
        blob_stream = blob_client.download_blob(offset=2+size_ct, length=2)
        size_iv = struct.unpack("H", blob_stream.content_as_bytes())[0]
        blob_stream = blob_client.download_blob(offset=4+size_ct, length=size_iv)
        iv_str = struct.unpack(str(size_iv)+"s", blob_stream.content_as_bytes())[0]
        # Now lets get the key from Vault
        self._init_cipher_params(self._param_key, iv_str, ct_str.decode(), new_key=False)
        #
        struct_format = self.STRUCT_FORMAT.format(len_kct=len(self._key_ciphertext),len_iv=len(self._iv))
        return struct.calcsize(struct_format)

    def _write_local_file(self, buffer, out_stream, size):
        out_stream.write(bytes(buffer[:size]))

    def _write_azure_blob(self, buffer, blob_client, size):
        b_id =  str(uuid.uuid4())
        blob_client.stage_block(block_id=b_id, data=bytes(buffer[:size]))
        self._block_list.append(BlobBlock(block_id=b_id))


    def _encrypt_stream(self,in_stream,out_stream,chunk_size=1048576):
        encryptor = self.cipher.encryptor()
        buf = bytearray(chunk_size + 15)
        while True:
            data = in_stream.read(chunk_size)
            if not data:
                break # done
            res = encryptor.update_into(data, buf)
            if self._buffer_writter == BufferWritter.LOCAL:
                self._write_local_file(buf,out_stream,res)
            elif self._buffer_writter == BufferWritter.AZURE:
                self._write_azure_blob(buf,out_stream,res)
        final = encryptor.finalize()
        if self._buffer_writter == BufferWritter.LOCAL:
            self._write_local_file(encryptor.tag,out_stream,len(encryptor.tag))
        elif self._buffer_writter == BufferWritter.AZURE:
            self._write_azure_blob(encryptor.tag,out_stream,len(encryptor.tag))
        self._tag=encryptor.tag

    def _blob_read(self,blob_client,chunk_size):
        blob_stream = blob_client.download_blob(offset=self._blob_pos, length=chunk_size)
        bytes_received = blob_stream.content_as_bytes()
        self._blob_pos = self._blob_pos + len(bytes_received)
        return bytes_received

    
    def _decrypt_azure_stream(self,blob_client,out_stream,src_file_size,header_size,chunk_size=1048576):
        decryptor = self.cipher.decryptor()
        buf = bytearray(chunk_size + 15)
        encrypted_data_size = src_file_size - header_size - 16
        self._blob_pos=header_size
        for _ in range(int(encrypted_data_size / chunk_size)):
            data = self._blob_read(blob_client,chunk_size)
            if not data:
                break # done
            len_decrypted = decryptor.update_into(data, buf)
            self._write_local_file(buf,out_stream,len_decrypted)
        data = self._blob_read(blob_client,int(encrypted_data_size % chunk_size))
        len_decrypted = decryptor.update_into(data, buf)
        self._write_local_file(buf,out_stream,len_decrypted)
        #out_stream.write(decryptor.finalize())
        out_stream.flush()
        try:
            self._tag = self._blob_read(blob_client,16)
            out_stream.write(decryptor.finalize_with_tag(self._tag))
            out_stream.flush()
        except InvalidTag as ex:
            raise Exception("Tag Verification failed.")
            out_stream.detach()
            #os.unlink(file_to_decrypt + '.dec.2')
            #self._tag=str(encryptor.tag.hex())

    def _decrypt_stream(self,in_stream,out_stream,encrypted_data_size,chunk_size=1048576):
        decryptor = self.cipher.decryptor()
        buf = bytearray(chunk_size + 15)
        #while True:
        for _ in range(int(encrypted_data_size / chunk_size)):
            data = in_stream.read(chunk_size)
            if not data:
                break # done
            len_decrypted = decryptor.update_into(data, buf)
            self._write_local_file(buf,out_stream,len_decrypted)
        data = in_stream.read(int(encrypted_data_size % chunk_size))
        len_decrypted = decryptor.update_into(data, buf)
        self._write_local_file(buf,out_stream,len_decrypted)
        #out_stream.write(decryptor.finalize())
        out_stream.flush()
        try:
            self._tag = in_stream.read(16)
            out_stream.write(decryptor.finalize_with_tag(self._tag))
            out_stream.flush()
        except InvalidTag as ex:
            raise Exception("Tag Verification failed.")
            out_stream.detach()
            #os.unlink(file_to_decrypt + '.dec.2')
            #self._tag=str(encryptor.tag.hex())

    def decrypt_localfile(self,src_path, dst_path=None):
        if dst_path is None:
            dst_path = src_path + ".decrypted"
        
        if not os.path.exists(src_path):
            raise Exception("Path doesn't exist")
        
        src_file_size = os.path.getsize(src_path)

        with open(dst_path, "wb") as out_stream:
            with open(src_path,"rb") as in_stream:
                header_size = self.parse_headers(in_stream)
                self.init_cipher()
                self._decrypt_stream(in_stream,out_stream,src_file_size - header_size - 16)

    def decrypt_azurefile(self,src_path, dst_path=None, container=None):
        if dst_path is None:
            dst_path = src_path + ".decrypted"
        
        # Validate that the source path exist
        self._vault_init()
        blob_client = self._init_blob(container,src_path)
        
        blob_props = blob_client.get_blob_properties()
        src_file_size = blob_props.size

        with open(dst_path, "wb") as out_stream:
            header_size = self.parse_blob_headers(blob_client)
            self.init_cipher()
            self._decrypt_azure_stream(blob_client,out_stream,src_file_size, header_size)
    
    def encrypt_localfile(self,src_path, dst_path=None):
        self._buffer_writter = BufferWritter.LOCAL
        if self._param_iv is None:
            iv = os.urandom(13)
        else:
            iv = self._param_iv

        self._init_cipher_params(self._param_key, iv, self._param_key_ciphertext)
        self.init_cipher()

        if dst_path is None:
            dst_path = src_path + "enc.bin"
        if not os.path.exists(src_path):
            raise Exception("Path doesn't exist")
        with open(dst_path, "wb") as out_stream:
            out_stream.write(self.build_headers())
            with open(src_path,"rb") as in_stream:
                self._encrypt_stream(in_stream,out_stream)

    def _init_blob(self,container_name, blob_name):
        read_response = self.vault.secrets.kv.read_secret_version(path='azure/storage/backups')
        connection_string = read_response['data']['data']['connection-string'].strip()
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        container_client = blob_service_client.get_container_client(container_name)
        return container_client.get_blob_client(blob_name)
    
    def encrypt_to_azure(self,src_path, dst_filename=None, container=None):
        self._buffer_writter = BufferWritter.AZURE
        if self._param_iv is None:
            iv = os.urandom(13)
        else:
            iv = self._param_iv

        self._init_cipher_params(self._param_key, iv, self._param_key_ciphertext)
        self.init_cipher()

        if dst_filename is None:
            dst_filename = src_path + "enc.bin"
        if not os.path.exists(src_path):
            raise Exception("Source file doesn't exist")

        #struct_format = self.STRUCT_FORMAT.format(len_kct=len(self._param_key_ciphertext),len_iv=len(iv))
        # File Headers
        encryption_header = self.build_headers()

        blob_client = self._init_blob(container,dst_filename)
        self._block_list = []

        b_id =  str(uuid.uuid4())
        blob_client.stage_block(block_id=b_id, data=encryption_header)
        self._block_list.append(BlobBlock(block_id=b_id))

        with open(src_path,"rb") as in_stream:
            self._encrypt_stream(in_stream,blob_client)
        blob_client.commit_block_list(self._block_list)

    def get_tag(self):
        return self._tag
    
    def set_tag(self,tag):
        self._tag = tag

if __name__ == '__main__':
    print ("Ready")
    # encryptor_local = BufferedAESGCM (
    #                 key_source=KeySource.LOCAL,
    #                 key=b64decode('MAY9TYzGcSrs3MxJ5NddFfvjFrLyb77OUT/hVzVMFnA='),
    #                 key_ciphertext="vault:v1:QEyGawHXukOyvkqU7GJXJODgLeqFXD04+pCJkKO5ocI8PnKYIE2KyBl1mWz6nD8U0uWpz0opIdpJnw7g"
    #             )
    # encryptor_local.encrypt_localfile("/home/manuel220/vault/publicrsa/medium.csv","./encrypted_local.bin")


    # encryptor_local_vault = BufferedAESGCM (
    #                 key_source=KeySource.HASHI_VAULT,
    #                 key="manzana"
    #             )
    # encryptor_local_vault.encrypt_localfile("/home/manuel220/vault/publicrsa/files/medium.csv","./encrypted_vault.bin")
    # time.sleep(2)
    
    # print (encryptor_local_vault.get_tag())


    # decryptor_local_vault = BufferedAESGCM (
    #                 key_source=KeySource.HASHI_VAULT,
    #                 key="manzana"
    #             )
    # decryptor_local_vault.decrypt_localfile("./encrypted_vault2.bin","./decrypted_vault_azure.csv")

    # encryptor_azure_vault = BufferedAESGCM (
    #                 key_source=KeySource.HASHI_VAULT,
    #                 key="manzana"
    #             )
    # encryptor_azure_vault.encrypt_to_azure("/home/manuel220/vault/publicrsa/files/medium.csv","encrypted_vault2.bin", container="backupstmp")

    decryptor_azure_vault = BufferedAESGCM (
                    key_source=KeySource.HASHI_VAULT,
                    key="manzana"
                )
    decryptor_azure_vault.decrypt_azurefile("encrypted_vault2.bin","./decrypted_vault_azure.csv", container="backupstmp")
    
    print ('Done')