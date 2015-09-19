var mongoose = require('mongoose');
var XssAttack = new mongoose.Schema(
    {
        Header:{},
        IP: String,
        Path:String,
        Scheme: String,
        Method: String,
        Payload: String,
        Port: String,
        OriginID:mongoose.Schema.Types.ObjectId,
        Result: String,
        Timestamp: Number,
    });


var XssAttacks = mongoose.model('XSSAttack',XssAttack,'XSSAttack');

module.exports = XssAttacks;
//实例化