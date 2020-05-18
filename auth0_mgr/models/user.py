import typing
import json
import abc


class Base(abc.ABC):

    @abc.abstractclassmethod
    def load(cls, **kwargs):
        return NotImplemented
    
    def to_dict(self) -> typing.Dict:
        ret: typing.Dict
        
        ret = {}
        for key, val in self.__dict__.items():
            if hasattr(val, "to_dict"):
                if callable(val.to_dict):
                    ret.update({key: val.to_dict()})
            if key not in ret:
                ret.update({key: val})
        return ret

    def dump(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def deserialize(cls, json_str: str):
        _dct = json.loads(json_str)
        return cls.load(_dct)

    def serialize(self) -> str:
        return self.dump()


class HashKey(Base):
    value: typing.Optional[str]
    encoding: typing.Optional[str]

    def __init__(self,
                 value: str = None, 
                 encoding: str = None):
        self.value = value
        self.encoding = encoding

    @classmethod
    def load(cls, **kwargs):
        return cls(**kwargs)



class Hash(Base):
    value: typing.Optional[str]
    encoding: typing.Optional[str]
    digest: typing.Optional[str]
    key: typing.Optional[HashKey]

    def __init__(self, 
                 value: str = None, 
                 encoding: str = None, 
                 digest: str = None, 
                 key: HashKey = None):
        self.value = value
        self.encoding = encoding
        self.digest = digest
        self.key = key

    @classmethod
    def load(cls, **kwargs):
        if kwargs.get("key", None):
            _key = HashKey.load(**kwargs["key"])
            kwargs.update({"key": _key})
        return cls(**kwargs)




class Salt(Base):
    value: typing.Optional[str]
    encoding: typing.Optional[str]
    position: typing.Optional[str]

    def __init__(self, 
                 value: str = None, 
                 encoding: str = None,
                 position: str = None):
        
        self.value = value
        self.encoding = encoding
        self.position = position

    @classmethod
    def load(cls, **kwargs):
        return cls(**kwargs)



class Password(Base):
    encoding: typing.Optional[str]
    
    def __init__(self, encoding:str  = None):
        self.encoding = encoding

    @classmethod
    def load(cls, **kwargs):
        return cls(**kwargs)



class Credentials(Base):
    hash: typing.Optional[Hash]
    algorithm: typing.Optional[str]
    salt: typing.Optional[Salt]
    password: typing.Optional[Password]

    def __init__(self, 
                 hash: Hash = None,
                 algorithm: str = None,
                 salt: Salt = None,
                 password: Password = None):
        self.hash = hash
        self.algorithm = algorithm
        self.salt = salt
        self.password = password

    @classmethod
    def load(cls, **kwargs):
        if kwargs.get("hash", None):
            _hash = Hash.load(**kwargs["hash"])
            kwargs.update("hash", _hash)
        if kwargs.get("password", None):
            _hash = Password.load(**kwargs["password"])
            kwargs.update("password", _hash)
        if kwargs.get("salt", None):
            _hash = Salt.load(**kwargs["salt"])
            kwargs.update("salt", _hash)
        return cls(**kwargs)
        


class Auth0User(Base):
    """
    Used for exchanging user data between auth0 database and applications
    """
    email: str
    email_verified: typing.Optional[bool]
    user_id: typing.Optional[str]
    username: typing.Optional[str]
    given_name: typing.Optional[str]
    family_name: typing.Optional[str]
    name: typing.Optional[str]  # Full name
    picture: typing.Optional[str]  # url to avatar
    blocked: typing.Optional[bool]
    custom_password_hash: typing.Optional[Credentials]
    app_metadata: typing.Dict
    user_metadata: typing.Dict

    API_UPDATEABLE_KEYS = [
        'app_metadata',
        'blocked',
        'email',
        'email_verified',
        'family_name',
        'given_name',
        'name',
        'nickname',
        'phone_number',
        'phone_verfied',
        'picture',
        'username',
        'user_metadata',
        'verify_email'
    ]
    # note: passowrd is api-updatable, but was deliberately omitted from this client

    APP_METADATA_KEYS = [
        'api_user_id',
        'roles',
        'privacy_policy_version',
        'terms_of_use_version',
        'permissions',
        'user_permissions'
    ]

    def __init__(self,
                 email, 
                 email_verified: bool = None,
                 user_id: str = None,
                 username: str = None,
                 given_name: str = None,
                 family_name: str = None,
                 nickname: str = None,
                 name: str = None,
                 picture: str = None,
                 blocked: bool = False,
                 phone_number: str = None,
                 phone_verfied: bool = None,
                 verify_email: bool = None, 
                 custom_password_hash: Credentials = None,
                 app_metadata: typing.Dict = {},
                 user_metadata: typing.Dict = {},
                 **kwargs):
        self.email = email 
        self.email_verified = email_verified 
        self.user_id = user_id 
        self.username = username
        self.nickname = nickname
        self.given_name = given_name 
        self.family_name = family_name 
        self.name = name
        self.picture = picture 
        self.blocked = blocked 
        self.custom_password_hash = custom_password_hash 
        self.app_metadata = app_metadata
        self.user_metadata = user_metadata
        self.phone_number = phone_number,
        self.phone_verfied = phone_verfied,
        if len(kwargs.keys()) > 0:
            for key, val in kwargs.items():
                if key in self.API_UPDATEABLE_KEYS:
                    self.user_metadata.update({key: val})
 

    def to_dict(self, api_updateable=True):
        dct = super(Auth0User, self).to_dict()
        to_pop = []
        if api_updateable:
            for key, val in dct.items():
                if key not in self.API_UPDATEABLE_KEYS:
                    to_pop.append(key)
                if not val: 
                    to_pop.append(key)
                try:
                    first = val[0]
                    if first is None:
                        to_pop.append(key)
                except Exception:
                    pass

        for key in to_pop:
            try:
                dct.pop(key)
            except Exception:
                pass
        return dct
        

    @classmethod
    def load(cls, **kwargs):
        if kwargs.get("custom_password_hash", None):
            creds = Credentials.load(**kwargs["custom_password_hash"])
            kwargs.update({"custom_password_hash": creds})
        email = kwargs.pop('email')
        return cls(email, **kwargs)

    def load_data(self, data: typing.Dict):
        for key, val in data.items():
            if key in self.API_UPDATEABLE_KEYS:
                setattr(self, key, val)
            elif key in self.APP_METADATA_KEYS:
                self.app_metadata.update({key: val})
            else:
                self.user_metadata.update({key: val})
