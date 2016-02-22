module.paths.push('/usr/local/lib/ldap-passwd/node_modules');

var fs = require('fs');
var nconf = require('nconf');
var ldap = require('ldapjs');
var auth = require('passwd-linux');

nconf.argv()
    .env()
    .file({ file: '/etc/ldap-passwd.json'});

nconf.defaults(
    {
        'debug': false,
        'interface': '127.0.0.1',
        'port': 1389,
        'org': 'o=example, o=com',
        'orgUnit': 'ou=Users',
        'ldapUser': 'ldapadmin',
        'ldapCredentials': 'secret',
        'processUser': 'nobody',
        'processGroup': 'shadow',
        }
    );

var ORG_DN = nconf.get('orgUnit') + ', ' + nconf.get('org');
var LDAP_USER_DN = "cn=" + nconf.get('ldapUser') + ", " + nconf.get('org');

///--- Shared handlers
function extractCN(req) {
    cn = req.dn.rdns[0].attrs.cn.value;
    if (!cn) {
        return undefined;
        }
    
    if (nconf.get('debug')) {
        console.log('cn = ' + cn);
        }
    return cn;
    }
    
function authorize(req, res, next) {
    if (nconf.get('debug')) {
        console.log('AUTHORIZE CALLED');
        console.log('BIND DN: ' + req.connection.ldap.bindDN.toString());
        console.log('REQUEST TYPE: ' + req.type);
        }

    if (
        (req.type != 'BindRequest' || req.type != 'SearchRequest') & 
        !req.connection.ldap.bindDN.equals(LDAP_USER_DN)
        ) {
            return next(new ldap.InsufficientAccessRightsError());
            }

    return next();
    }

function loadPasswdFile(req, res, next) {
    fs.readFile(
        '/etc/passwd', 
        'utf8', 
        function(err, data) {
            if (err) {
                return next(new ldap.OperationsError(err.message));
                }

            req.users = {};
            var lines = data.split('\n');
            for (var i = 0; i < lines.length; i++) {
                if (!lines[i] || /^#/.test(lines[i])) {
                    continue;
                    }

                var record = lines[i].split(':');
                if (!record || !record.length) {
                    continue;
                    }

                req.users[record[0]] = {
                    dn: 'cn=' + record[0] + ', ' + ORG_DN,
                    attributes: {
                        cn: record[0],
                        pwd: record[1],
                        uid: record[2],
                        gid: record[3],
                        description: record[4],
                        homedirectory: record[5],
                        shell: record[6] || '',
                        objectclass: 'unixUser'
                        }
                    };
                }

            return next();
            }
        );
    }

var pre = [authorize, loadPasswdFile];

///--- Mainline
var server = ldap.createServer();

server.bind(
    nconf.get('org'), 
    pre,
    function(req, res, next) {
        if (nconf.get('debug')) {
            console.log('BIND CALLED');
            console.log('BIND DN: %s', req.dn.valueOf());
            }

        // Check admin credentials here
        if (req.dn.toString() == LDAP_USER_DN) {
            if (req.credentials !== nconf.get('ldapCredentials')) {
                return next(new ldap.InvalidCredentialsError());
                }
            res.end();
            return next();    
            }

        // Check user credentials here
        login = extractCN(req);
        if (!login) {
            return next(new ldap.ConstraintViolationError('cn required'));
            }
        auth.checkPass(
            login, 
            req.credentials, 
            function (error, response) {
                "use strict";
                if (error) {
                    console.log("AUTH ERROR for " + login + ": " + error);
                    } 
                else {
                    if (response == "passwordIncorrect") {
                        if (nconf.get('debug')) {
                            console.log("Bad Password for:" + login); 
                            }
                        return next(new ldap.InvalidCredentialsError());
                        }
                    }

                // If we got here, the login was good
                if (nconf.get('debug')) {
                    console.log("AUTH SUCCEEDED for:" + login); 
                    }
                res.end();
                return next();
                }
            );            
        
        res.end();
        return next();
        }
    );

server.search(
    nconf.get('org'), 
    pre, 
    function(req, res, next) {  
        if (nconf.get('debug')) {
            console.log('SEARCH CALLED on: ' + JSON.stringify(req.dn));
            }
        
        Object.keys(req.users).forEach(
            function(k) {
                if (req.filter.matches(req.users[k].attributes)) {
                    res.send(req.users[k]);
                    }
                }
            );
        
        res.end();
        return next();
        }
    );

server.add(
    nconf.get('org'),  
    pre, 
    function(req, res, next) {
        return next(new ldap.UnwillingToPerformError("Only 'search' and' bind' supported"));

        if (!req.dn.rdns[0].cn)
            return next(new ldap.ConstraintViolationError('cn required'));

        if (req.users[req.dn.rdns[0].cn])
            return next(new ldap.EntryAlreadyExistsError(req.dn.toString()));

        var entry = req.toObject().attributes;

        if (entry.objectclass.indexOf('unixUser') === -1)
            return next(new ldap.ConstraintViolation('entry must be a unixUser'));

        var opts = ['-m'];
        if (entry.description) {
            opts.push('-c');
            opts.push(entry.description[0]);
            }
        if (entry.homedirectory) {
            opts.push('-d');
            opts.push(entry.homedirectory[0]);
            }
        if (entry.gid) {
            opts.push('-g');
            opts.push(entry.gid[0]);
            }
        if (entry.shell) {
            opts.push('-s');
            opts.push(entry.shell[0]);
            }
        if (entry.uid) {
            opts.push('-u');
            opts.push(entry.uid[0]);
            }
        opts.push(entry.cn[0]);
        var useradd = spawn('useradd', opts);

        var messages = [];

        useradd.stdout.on(
            'data', 
            function(data) {
                messages.push(data.toString());
                }
            );
        useradd.stderr.on(
            'data', 
            function(data) {
                messages.push(data.toString());
                }
            );

        useradd.on(
            'exit', 
            function(code) {
                if (code !== 0) {
                var msg = '' + code;
                if (messages.length)
                    msg += ': ' + messages.join();
                return next(new ldap.OperationsError(msg));
                }

                res.end();
                return next();
                }
            );
        }
    );


server.modify(
    ORG_DN, 
    pre, 
    function(req, res, next) {
        return next(new ldap.UnwillingToPerformError("Only 'search' and' bind' supported"));
        
        if (!req.dn.rdns[0].cn || !req.users[req.dn.rdns[0].cn])
            return next(new ldap.NoSuchObjectError(req.dn.toString()));

        if (!req.changes.length)
            return next(new ldap.ProtocolError('changes required'));

        var user = req.users[req.dn.rdns[0].cn].attributes;
        var mod;

        for (var i = 0; i < req.changes.length; i++) {
            mod = req.changes[i].modification;
            switch (req.changes[i].operation) {
                case 'replace':
                //if (mod.type !== 'userpassword' || !mod.vals || !mod.vals.length)
                return next(new ldap.UnwillingToPerformError('only password updates ' +
                                                            'allowed'));
                break;
                
                case 'add':
                case 'delete':
                    return next(new ldap.UnwillingToPerformError('only replace allowed'));
                }
            }

        var passwd = spawn('chpasswd', ['-c', 'MD5']);
        passwd.stdin.end(user.cn + ':' + mod.vals[0], 'utf8');

        passwd.on(
            'exit', 
            function(code) {
                if (code !== 0)
                return next(new ldap.OperationsError('' + code));

                res.end();
                return next();
                }
            );
        }
    );


server.del(
    ORG_DN, 
    pre, 
    function(req, res, next) {
        return next(new ldap.UnwillingToPerformError("Only 'search' and' bind' supported"));

        if (!req.dn.rdns[0].cn || !req.users[req.dn.rdns[0].cn])
            return next(new ldap.NoSuchObjectError(req.dn.toString()));

        var userdel = spawn('userdel', ['-f', req.dn.rdns[0].cn]);

        var messages = [];
        userdel.stdout.on('data', function(data) {
            messages.push(data.toString());
        });
        userdel.stderr.on('data', function(data) {
            messages.push(data.toString());
        });

        userdel.on('exit', function(code) {
            if (code !== 0) {
            var msg = '' + code;
            if (messages.length)
                msg += ': ' + messages.join();
            return next(new ldap.OperationsError(msg));
            }

            res.end();
            return next();
        });
    });


// LDAP "standard" listens on 389, but whatever.
server.listen(
    nconf.get('port'), 
    nconf.get('interface'), 
    function() {
        console.log('/etc/passwd LDAP server up at: %s', server.url);
        }
    );


