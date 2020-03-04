var crypto = require('crypto');

function remove_eqal_sign (str){
    for(i=1 ; i<=3 ; i++){
        str  = str.replace(/=$/, '');
    }
    return str
}

function add_eql_sign(str){
    if(str.length % 4 == 3){
        str = str+'=';
    }
    else if(str.length % 4 == 2){
        str = str+'==';
    }
    else if(str.length % 4 == 1){
        str = str+'===';
    }
    return str;
}

let jwt = {  
    
    //------------------------------- data encode---------------------------//
    encode : function( data , secret , header ={ "alg": "HS256", "typ": "JWT" } ) {

        if(Object.keys(data).length >= 1 && secret.length > 5 ){
            base64_header  = Buffer.from(JSON.stringify(header)).toString('base64')
            base64_header  = remove_eqal_sign(base64_header)
            
            base64_data  = Buffer.from(JSON.stringify(data)).toString('base64');
            base64_data  = remove_eqal_sign(base64_data)
            
            payload = base64_header+"." +base64_data;
            
            final_result = crypto.createHmac('sha256', secret ).update(payload).digest("base64");
            final_result = payload+"."+remove_eqal_sign(final_result)
    
            return final_result;
        }
        else{
            return false;
        }
        
    },


    //------------------------------- data decode---------------------------//
    decode : function( encodedata , secret) {
        if(encodedata.length > 24){
            data_array = encodedata.split("."); 
            payload  = data_array[0]+'.'+data_array[1];

            base64_data = add_eql_sign(data_array[1]);
            data = JSON.parse(Buffer.from(base64_data, 'base64').toString()) 

            //------------ if there is an exp date -------------//
            if(data.exp){
                jwt_unix_time_stamp = Date.now() / 1000 | 0 ;
                if(jwt_unix_time_stamp > data.exp ){                   

                    encoded_by_clientJWT= crypto.createHmac('sha256', secret ).update(payload).digest("base64");
                    encoded_by_clientJWT = remove_eqal_sign(encoded_by_clientJWT)
    
                    if( data_array[2] == encoded_by_clientJWT ) {                   
                        return data
                    }
                    else{
                        return false
                    }
                }
                else{
                    return false
                }
            }
            //------------ if there is no an exp date -------------//
            else{
                encoded_by_clientJWT= crypto.createHmac('sha256', secret ).update(payload).digest("base64");
                encoded_by_clientJWT = remove_eqal_sign(encoded_by_clientJWT)
    
                if( data_array[2] == encoded_by_clientJWT ) {                   
                    return data
                }
                else{
                    return false
                }
            }
            

            
        }
    },

};


module.exports = jwt;