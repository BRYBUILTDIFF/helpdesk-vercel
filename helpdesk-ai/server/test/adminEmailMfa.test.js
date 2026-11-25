const {test,beforeEach}=require('node:test');
const assert=require('node:assert/strict');
process.env.SECURITY_ENCRYPTION_KEY='b'.repeat(64);
process.env.JWT_ACCESS_SECRET='test-email-mfa-access-secret-at-least-32-characters';
let record,delivered,failDelivery;
const user={id:7,email:'admin@example.test',isActive:true,role:'ADMIN',tokenVersion:3,passwordHash:'hash'};
const db={
 user:{findUnique:async()=>user},
 $queryRaw:async()=>record?[record]:[],
 $executeRaw:async(parts,...values)=>{
  const sql=parts.join('?');
  if(sql.startsWith('INSERT'))record={...(record||{}),userId:values[0],pendingSecret:values[1],pendingExpiresAt:values[2]};
  else if(sql.includes('"recoveryHashes"'))Object.assign(record,{secret:values[0],pendingSecret:null,pendingExpiresAt:null});
  else if(sql.includes('SET "pendingSecret"'))record.pendingSecret=values[0];
  return 1;
 },
 $transaction:async fn=>{const prior=record&&{...record};try{return await fn(db);}catch(e){record=prior;throw e;}}
};
require.cache[require.resolve('../src/prisma')]={exports:db};
require.cache[require.resolve('../src/utils/password')]={exports:{comparePassword:async plain=>plain==='correct'}};
require.cache[require.resolve('../src/services/adminEmail')]={exports:{sendCode:async(email,code)=>{if(failDelivery)throw new Error('delivery failed');delivered={email,code};}}};
const controller=require('../src/controllers/adminMfaController');
const mfa=require('../src/services/adminMfa');
const req=(body={})=>({user,body:{password:'correct',...body},headers:{}});
const res=()=>({statusCode:200,status(code){this.statusCode=code;return this;},json(body){this.body=body;return this;}});
const next=e=>{throw e;};
beforeEach(()=>{record=null;delivered=null;failDelivery=false;});
test('email code goes only to the stored admin address and is consumed once',async()=>{
 const send=res();await controller.enroll(req({email:'attacker@example.test'}),send,next);
 assert.equal(delivered.email,user.email);assert.match(delivered.code,/^\d{6}$/);assert.equal(send.body.code,undefined);
 const verify=res();await controller.verify(req({code:delivered.code}),verify,next);
 assert.ok(mfa.verifyProof(verify.body.verificationToken,user,record.secret));
 const replay=res();await controller.verify(req({code:delivered.code}),replay,next);assert.equal(replay.statusCode,400);
});
test('expired codes and codes issued before a password change fail',async()=>{
 await controller.enroll(req(),res(),next);record.pendingExpiresAt=new Date(Date.now()-1);
 let result=res();await controller.verify(req({code:delivered.code}),result,next);assert.equal(result.statusCode,400);
 await controller.enroll(req(),res(),next);user.tokenVersion++;
 try{result=res();await controller.verify(req({code:delivered.code}),result,next);assert.equal(result.statusCode,400);}finally{user.tokenVersion--;}
});
test('five wrong attempts exhaust a challenge and immediate resend is limited',async()=>{
 await controller.enroll(req(),res(),next);
 const limited=res();await controller.enroll(req(),limited,next);assert.equal(limited.statusCode,429);
 const wrong=delivered.code==='000000'?'111111':'000000';
 for(let i=0;i<5;i++){const result=res();await controller.verify(req({code:wrong}),result,next);assert.equal(result.statusCode,400);}
 const result=res();await controller.verify(req({code:delivered.code}),result,next);assert.equal(result.statusCode,400);
});
test('resending replaces the previous code and legacy authenticator state',async()=>{
 record={secret:'old-authenticator',pendingSecret:null,pendingExpiresAt:null};
 await controller.enroll(req(),res(),next);const old=delivered.code;record.pendingExpiresAt=new Date(Date.now()+230000);
 await controller.enroll(req(),res(),next);
 if(old!==delivered.code){const result=res();await controller.verify(req({code:old}),result,next);assert.equal(result.statusCode,400);}
 const result=res();await controller.verify(req({code:delivered.code}),result,next);assert.ok(record.secret.startsWith('email:'));assert.ok(result.body.verificationToken);
});
test('wrong password does not send email; delivery failure rolls back challenge',async()=>{
 await assert.rejects(()=>controller.enroll(req({password:'bad'}),res(),next));assert.equal(delivered,null);
 failDelivery=true;await assert.rejects(()=>controller.enroll(req(),res(),next));assert.equal(record,null);
});
