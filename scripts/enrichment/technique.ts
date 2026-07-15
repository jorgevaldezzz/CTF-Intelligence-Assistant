export function extractTechniques(text:string):string[] {

const patterns:Record<string,RegExp>={

"SSRF":/\bssrf|server[- ]side request forgery\b/i,

"SQL Injection":/\bsql\s*injection|sqli\b/i,

"XSS":/\bxss|cross[- ]site scripting\b/i,

"Path Traversal":/\bpath traversal|directory traversal\b/i,

"XXE":/\bxxe|xml external entity\b/i,

"Command Injection":/\bcommand injection|os command\b/i,

"Buffer Overflow":/\bbuffer overflow\b/i,

"JWT Attack":/\bjwt|json web token\b/i,

"Deserialization":/\bdeserializ/i,

"Privilege Escalation":/\bprivilege escalation\b/i,

"Cloud Metadata":/\b169\.254\.169\.254|metadata service|imds\b/i,

};


return Object.entries(patterns)
.filter(([_,regex])=>regex.test(text))
.map(([name])=>name);

}