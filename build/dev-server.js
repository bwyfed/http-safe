/**
 * Created by Bianwangyang on 2017/8/16.
 */

const opn = require('opn');
const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

const port = 3000;
const uri = 'http://localhost:' + port + '/index.html';
app.use(express.static(path.join(__dirname,'../client')));   //托管静态资源
// app.use(express.static(path.join(__dirname,'../client/index.html')));
app.use('/api/whitelist', function(req, res){
    fs.readFile(path.join(__dirname, "../server/whitelist.json"), function (err,data) {
        if(err) {
            console.log(err.stack);
            return;
        }
        console.log(data.toString());
        let senddata = data.toString();
        res.send(senddata);
    });
});

app.use('/api/report', function(req, res) {
    console.log(req);
    res.end("report success");
});
app.use('/',function (req,res) {
    res.sendFile(path.join(__dirname,'../client/index.html'));
});
app.listen(port);

console.log('Server running at '+ uri +'\n');
opn(uri);

module.exports = app;