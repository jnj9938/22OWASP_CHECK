var express = require('express');
var app = express();
var path = require('path');
var url = require('url');
var template = require('./lib/template.js')
var bodyParser = require('body-parser');
var mysql = require('mysql');
var MySQLStore = require('express-mysql-session');
var flash = require('connect-flash');
var spawn = require('child_process').spawn;
var session = require('express-session');
const { Script } = require('vm');

var db = mysql.createConnection({
  host    : 'localhost',
  user    : 'root',
  password : '9938',
  database : 'result'
})

var options= {
  host    : 'localhost',
  user    : 'root',
  password : '9938',
  database : 'result'
}
var sessionStore = new MySQLStore(options);


db.connect();
app.set('veiw engine', 'ejs');
app.set('views','./views');
app.use(express.static(path.join(__dirname, '/public')));
app.use(bodyParser.urlencoded({ extended: false}));
app.use(flash());
app.use(session({
  secret: 'sessionKey',
  resave: false,
  saveUninitialized: true,
  store: sessionStore
}));

app.get('/', function(request, response){
  if(request.session.isLogined){
    response.render(__dirname+'/views/member.ejs');
  }
  else{
    response.render(__dirname+'/views/index.ejs');
  }
  
});

app.get('/profile', function(request, response){
  if(request.session.isLogined){
    response.render(__dirname+'/views/profile_logined.ejs');
  }
  else{
    response.render(__dirname+'/views/profile.ejs');
  }
});


app.get('/member_data', function(request, response){
  if(request.session.isLogined){
    db.query(`SELECT * FROM resultlist WHERE name='${request.session.userId}'`, function(err, _url){
        if(err){throw err}
        var list = template.list(_url);
        var html = template.HTML(list);
        response.send(html);
      });
  }
  else{
    response.send('<script>alert("로그인이 필요합니다")</script>');
  }
  
});

app.get('/member_record/:userId', function(request, response){
  if(request.session.isLogined){
    db.query(`SELECT * FROM resultlist WHERE id='${request.params.userId}'`, function(err, record){
        if(err){throw err;}
        var html = template.result(record[0].sqlin, record[0].sql_info, record[0].CSRF, record[0].CSRF_info, record[0].cookie, record[0].cookie_info, record[0].http, record[0].http_info, record[0].bruteForce, record[0].bruteForce_info, record[0].XSS, record[0].XSS_info, record[0].base64Vul, record[0].sessionVul, record[0].sniff);
        response.send(html);
      });
    }
  else{
    response.send('<script>alert("로그인이 필요합니다")</script>');
  }
  
});

app.get('/register', function(request, response) {
  response.render(__dirname+'/views/register.ejs')
})

app.post('/register_process', function(request, response) {
  var name = request.body.name
  var pwd = request.body.pwd
  var nick = request.body.nick
  var emailad = request.body.emailad
  db.query('SELECT name FROM member where name=?', [name],function(err,rows){
    if(rows.length){
      response.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});  
      response.write('<script>alert("중복되는 아이디입니다")</script>');
      response.write('<script>window.location.href="http://localhost:3000/register"</script>');
    } else {
      db.query(`INSERT INTO member (name, pwd, nick, emailad) VALUES ('${name}', '${pwd}','${nick}', '${emailad}')`,function(err,rows){
        if(err) throw err;
      response.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});  
      response.write('<script>alert("회원가입을 완료했습니다")</script>');
      response.write('<script>window.location.href="http://localhost:3000/"</script>');
      })
    } 
  });
});

app.get('/login', function(request, response) {
  response.render(__dirname+'/views/login.ejs')
})

app.post('/login_process', function(request, response) {
  var name = request.body.name
  var pwd = request.body.pwd
  var sql_insert={name:name,pwd,pwd}
  db.query('SELECT * FROM member where name=?', [name],function(err,rows){
    if(err){
      throw err
    }
    if(rows.length){
      if(rows[0].name === name){
        db.query('SELECT * FROM member where pwd=?', [pwd],function(err,rows){
          if(err){
            throw err
          }
          if(rows.length){
            request.session.userId=rows[0].name
            request.session.password=rows[0].pwd
            request.session.isLogined=true;
            request.session.save(function(){
              response.redirect('/')
            })
          }else {
            response.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
            response.write('<script>alert("비밀번호가 틀립니다")</script>');
            response.write('<script>window.location.href="http://localhost:3000/login"</script>');
          }
        })
      }
    } else {
      response.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});  
      response.write('<script>alert("아이디가 틀립니다")</script>');
      response.write('<script>window.location.href="http://localhost:3000/login"</script>');
  }
  });
});

app.get('/logout', function(request, response){
  delete request.session.userId;
  delete request.session.password;
  delete request.session.isLogined;
  request.session.save(function(){
    response.redirect('/')
  })
})

app.get('/result_process', function(request, response){
    var _url = request.url
    var queryData = url.parse(_url, true).query;
    var result = spawn('python', ['webvul.py', queryData.id]);
    result.stdout.on('data', function(data){                     //data는 python에서 json타입으로 넘어옴 
        var list = data.toString();
        var json_data=JSON.parse(list);
        
        db.query(
         `INSERT INTO resultlist  (name, URL, sqlin, sql_info, CSRF, CSRF_info, cookie, cookie_info, http, http_info, bruteForce, bruteForce_info, XSS, XSS_info, base64Vul, sessionVul, sniff) VALUES ('${request.session.userId}', '${queryData.id}', '${json_data['sqlin']}','${json_data['sql_info']}', '${json_data['CSRF']}', '${json_data['CSRF_info']}', '${json_data['cookie']}', '${json_data['cookie_info']}', '${json_data['http']}', '${json_data['http_info']}', '${json_data['bruteForce']}', '${json_data['bruteForce_info']}', '${json_data['XSS']}', '${json_data['XSS_info']}', "${json_data['base64Vul']}", '${json_data['sessionVul']}', '${json_data['sniff']}')`
         
        , function(error, result){
            if(error){
                throw error;
            }
        })
        
        response.render('result.ejs', json_data); 
    });
    result.stderr.on('data', function(data) {
        response.send(data.toString());
    });
});

app.get('/XSS', function(request, response){
  if(request.session.isLogined){
    response.render('ST_XSS.ejs');
  }
  else{
    response.send('<script>alert("로그인이 필요합니다")</script>');
  }
  
});
app.get('/SQLINJECTION', function(request, response){
  if(request.session.isLogined){
    response.render('ST_SQL.ejs');
  }
  else{
    response.send('<script>alert("로그인이 필요합니다")</script>');
  }
  
});
app.get('/CSRF', function(request, response){
  if(request.session.isLogined){
    response.render('ST_CSRF.ejs');
  }
  else{
    response.send('<script>alert("로그인이 필요합니다")</script>');
  }
  
});
app.get('/BRUTE', function(request, response){
  if(request.session.isLogined){
    response.render('ST_BRUTE.ejs');
  }
  else{
    response.send('<script>alert("로그인이 필요합니다")</script>');
  }
  
});
app.get('/PLAIN', function(request, response){
  if(request.session.isLogined){
    response.render('ST_PLAIN.ejs');
  }
  else{
    response.send('<script>alert("로그인이 필요합니다")</script>');
  }
  
});
app.get('/COOKIE', function(request, response){
  if(request.session.isLogined){
    response.render('ST_COOKIE.ejs');
  }
  else{
    response.send('<script>alert("로그인이 필요합니다")</script>');
  }
  
});
app.get('/SNIFF', function(request, response){
  if(request.session.isLogined){
    response.render('ST_SNIFF.ejs');
  }
  else{
    response.send('<script>alert("로그인이 필요합니다")</script>');
  }
  
});
app.get('/SESSION', function(request, response){
  if(request.session.isLogined){
    response.render('ST_SESSION.ejs');
  }
  else{
    response.send('<script>alert("로그인이 필요합니다")</script>');
  }
  
});
app.get('/LOCAL', function(request, response){
  if(request.session.isLogined){
    response.render('ST_LOCAL.ejs');
  }
  else{
    response.send('<script>alert("로그인이 필요합니다")</script>');
  }
  
});



app.listen(3000, function() {
    
})