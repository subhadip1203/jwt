var jwt = require('./index');


let header = {
    "alg": "HS256",
    "typ": "JWT"
};

let data = {
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022
}

secret = '1101tech'

encoded_data = jwt.encode(data, secret ,header) ;

console.log(encoded_data);

decode_data = jwt.decode(encoded_data , secret) ;


console.log(decode_data);