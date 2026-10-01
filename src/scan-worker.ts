import { scanSource } from './scanner.js';
process.once('message',async(message:{root:string;limits:Parameters<typeof scanSource>[1]})=>{
  try{process.send?.({result:await scanSource(message.root,message.limits)});}
  catch(error){process.send?.({error:error instanceof Error?error.message:String(error)});}
  finally{process.disconnect?.();}
});
