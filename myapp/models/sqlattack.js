var mongoose = require('mongoose');
var SQLattack = new mongoose.Schema(
    {
        Header:{},
        IP: String,
        Path:String,
        Scheme: String,
        Method: String,
        Payload: String,
        Port: String,
        OriginID:mongoose.Schema.Types.ObjectId,
        Result: {},
        Level: Number,
        Dbms: String,
        Timestamp: Number,
        
    });


var SQLattacks = mongoose.model('SQLAttack',SQLattack,'SQLAttack');

module.exports = SQLattacks;
//实例化