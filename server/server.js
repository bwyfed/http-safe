/**
 * Created by Bianwangyang on 2017/8/15.
 */
const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
/*
fs.readFile("./server/whitelist.json", function (err,data) {
    if(err) {
        console.log(err.stack);
        return;
    }
    console.log(data.toString());
    let senddata = data.toString();
});
*/
app.use('/api/whitelist', function(req, res){
    fs.readFile(path.join(__dirname, "whitelist.json"), function (err,data) {
        if(err) {
            console.log(err.stack);
            return;
        }
        console.log(data.toString());
        let senddata = data.toString();
        res.send(senddata);
    });
});

app.listen(3000);
console.log('Server running at http://localhost:3000');

module.exports = app;