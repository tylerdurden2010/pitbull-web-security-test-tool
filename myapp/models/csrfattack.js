var mongoose = require('mongoose');
var CSRFattack = new mongoose.Schema(
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
        Timestamp: Number,
    });


var CSRFattacks = mongoose.model('CSRFAttack',CSRFattack,'CSRFAttack');

module.exports = CSRFattacks;
//实例化