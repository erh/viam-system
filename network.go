package viamsystem

import (
 "context"
 "fmt"
 "io"
 "net"
 "net/http"
 "os"
 "strconv"
 "strings"
 "sync"
 "time"

 "go.viam.com/rdk/components/generic"
 "go.viam.com/rdk/logging"
 "go.viam.com/rdk/resource"
 "go.viam.com/rdk/spatialmath"
)

var NetworkModel = family.WithModel("network")

func init() {
 resource.RegisterComponent(generic.API, NetworkModel, resource.Registration[resource.Resource, *networkConfig]{Constructor: newNetwork})
}

type networkConfig struct {
 AllowedCIDRs []string `json:"allowed_cidrs"`
 TimeoutMS int `json:"timeout_ms"`
 MaxHosts int `json:"max_hosts"`
}
func (c *networkConfig) Validate(path string) ([]string, []string, error) {
 for _, s := range c.AllowedCIDRs { if _,_,err:=net.ParseCIDR(s); err!=nil { return nil,nil,fmt.Errorf("invalid allowed CIDR %q: %w",s,err) } }
 if c.MaxHosts < 0 || c.MaxHosts > 4096 { return nil,nil,fmt.Errorf("max_hosts must be 0..4096") }
 if c.TimeoutMS < 0 || c.TimeoutMS > 30000 { return nil,nil,fmt.Errorf("timeout_ms must be 0..30000") }
 return nil,nil,nil
}
type networkComponent struct {
 resource.AlwaysRebuild
 name resource.Name
 cfg *networkConfig
}
func newNetwork(ctx context.Context, deps resource.Dependencies, conf resource.Config, logger logging.Logger) (resource.Resource,error) {
 c,err:=resource.NativeConfig[*networkConfig](conf);if err!=nil{return nil,err}
 return &networkComponent{name:conf.ResourceName(),cfg:c},nil
}
func (n *networkComponent) Name() resource.Name{return n.name}
func (n *networkComponent) Close(context.Context) error{return nil}
func (n *networkComponent) Geometries(context.Context,map[string]interface{}) ([]spatialmath.Geometry,error){return nil,nil}
func (n *networkComponent) timeout() time.Duration { v:=n.cfg.TimeoutMS;if v==0 {v=750};return time.Duration(v)*time.Millisecond }
func (n *networkComponent) allowed(ip net.IP) bool {
 if ip==nil || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {return false}
 if len(n.cfg.AllowedCIDRs)>0 {for _,s:=range n.cfg.AllowedCIDRs {_,sub,_:=net.ParseCIDR(s);if sub.Contains(ip){return true}};return false}
 // Without an explicit allowlist, restrict probes to private/link-local destinations.
 return ip.IsPrivate() || ip.IsLinkLocalUnicast()
}
func (n *networkComponent) resolve(ctx context.Context,host string)([]net.IP,error){
 ips,err:=net.DefaultResolver.LookupIP(ctx,"ip",host);if err!=nil{return nil,err}
 for _,ip:=range ips {if !n.allowed(ip){return nil,fmt.Errorf("destination %s is outside allowed networks",ip)}}
 return ips,nil
}
func stringArg(m map[string]interface{},key string)(string,error){v,ok:=m[key].(string);if !ok||v=="" {return "",fmt.Errorf("%s must be a nonempty string",key)};return v,nil}
func intArg(m map[string]interface{},key string,def int)(int,error){v,ok:=m[key];if !ok{return def,nil};f,ok:=v.(float64);if !ok {if i,yes:=v.(int);yes{return i,nil};return 0,fmt.Errorf("%s must be a number",key)};if f!=float64(int(f)){return 0,fmt.Errorf("%s must be an integer",key)};return int(f),nil}
func (n *networkComponent) DoCommand(ctx context.Context,cmd map[string]interface{})(map[string]interface{},error){
 action,err:=stringArg(cmd,"command");if err!=nil{return nil,err}
 switch action {
 case "interfaces":
  ifaces,err:=net.Interfaces();if err!=nil{return nil,err}
  out:=[]interface{}{}
  for _,i:=range ifaces {addrs,_:=i.Addrs();a:=[]string{};for _,x:=range addrs{a=append(a,x.String())};out=append(out,map[string]interface{}{"name":i.Name,"mtu":i.MTU,"mac":i.HardwareAddr.String(),"flags":i.Flags.String(),"addresses":a})}
  return map[string]interface{}{"interfaces":out},nil
 case "neighbors":
  // Linux neighbor cache is informational; no privileged commands.
  data,err:=os.ReadFile("/proc/net/arp");if err!=nil{return nil,fmt.Errorf("neighbors unavailable on this platform: %w",err)}
  rows:=[]interface{}{};for idx,line:=range strings.Split(strings.TrimSpace(string(data)),"\n"){if idx==0{continue};f:=strings.Fields(line);if len(f)>=6{rows=append(rows,map[string]interface{}{"ip":f[0],"mac":f[3],"interface":f[5]})}}
  return map[string]interface{}{"neighbors":rows},nil
 case "dns":
  host,err:=stringArg(cmd,"host");if err!=nil{return nil,err}
  ips,err:=net.DefaultResolver.LookupIP(ctx,"ip",host);if err!=nil{return nil,err};out:=[]string{};for _,ip:=range ips{out=append(out,ip.String())};return map[string]interface{}{"addresses":out},nil
 case "tcp","http":
  host,err:=stringArg(cmd,"host");if err!=nil{return nil,err}
  ips,err:=n.resolve(ctx,host);if err!=nil{return nil,err};if len(ips)==0{return nil,fmt.Errorf("no addresses")}
  port,err:=intArg(cmd,"port",80);if err!=nil||port<1||port>65535{return nil,fmt.Errorf("invalid port")}
  cctx,cancel:=context.WithTimeout(ctx,n.timeout());defer cancel()
  addr:=net.JoinHostPort(ips[0].String(),strconv.Itoa(port))
  if action=="tcp"{conn,err:=(&net.Dialer{}).DialContext(cctx,"tcp",addr);if err!=nil{return map[string]interface{}{"reachable":false,"error":err.Error()},nil};conn.Close();return map[string]interface{}{"reachable":true,"address":addr},nil}
  path:="/";if v,ok:=cmd["path"].(string);ok{path=v};if !strings.HasPrefix(path,"/")||strings.HasPrefix(path,"//"){return nil,fmt.Errorf("path must start with one slash")}
  // Pin the resolved IP to avoid DNS rebinding and disable redirects/proxies.
  tr:=&http.Transport{Proxy:nil,DialContext:func(ctx context.Context,network,address string)(net.Conn,error){return (&net.Dialer{}).DialContext(ctx,network,addr)}};defer tr.CloseIdleConnections()
  client:=&http.Client{Transport:tr,Timeout:n.timeout(),CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}
  req,err:=http.NewRequestWithContext(cctx,"GET","http://"+net.JoinHostPort(host,strconv.Itoa(port))+path,nil);if err!=nil{return nil,err}
  resp,err:=client.Do(req);if err!=nil{return nil,err};defer resp.Body.Close()
  body,err:=io.ReadAll(io.LimitReader(resp.Body,2048));if err!=nil{return nil,err}
  return map[string]interface{}{"status":resp.StatusCode,"body":string(body),"address":addr},nil
 case "scan":
  subnet,err:=stringArg(cmd,"subnet");if err!=nil{return nil,err}
  ip,cidr,err:=net.ParseCIDR(subnet);if err!=nil||ip.To4()==nil{return nil,fmt.Errorf("scan requires an IPv4 CIDR")}
  max:=n.cfg.MaxHosts;if max==0{max=256}
  ones,bits:=cidr.Mask.Size();if bits!=32||ones<20||ones>32{return nil,fmt.Errorf("scan prefix must be /20 through /32")}
  count:=uint64(1)<<uint(bits-ones);if count>uint64(max){return nil,fmt.Errorf("subnet exceeds max_hosts (%d)",max)}
  ports:=[]int{80,443,8080};if raw,ok:=cmd["ports"].([]interface{});ok{ports=nil;for _,p:=range raw{f,ok:=p.(float64);if !ok||f!=float64(int(f))||f<1||f>65535{return nil,fmt.Errorf("invalid port")};ports=append(ports,int(f))};if len(ports)>16{return nil,fmt.Errorf("too many ports")}}
  base:=cidr.IP.To4();if base==nil{return nil,fmt.Errorf("IPv4 required")}
  for j:=uint64(0);j<count;j++{addr:=make(net.IP,4);copy(addr,base);for k:=3;k>=0;k--{addr[k]+=byte(j>>(uint(3-k)*8))};if !n.allowed(addr){return nil,fmt.Errorf("subnet contains disallowed address %s",addr)}}
  sem:=make(chan struct{},32);var wg sync.WaitGroup;var mu sync.Mutex;found:=[]interface{}{}
  for j:=uint64(0);j<count;j++{
   addr:=make(net.IP,4);copy(addr,base);for k:=3;k>=0;k--{addr[k]+=byte(j>>(uint(3-k)*8))}
   wg.Add(1);go func(ip net.IP){defer wg.Done();select{case sem<-struct{}{}:case <-ctx.Done():return};defer func(){<-sem}()
    open:=[]int{};for _,port:=range ports{cctx,cancel:=context.WithTimeout(ctx,n.timeout());conn,e:=(&net.Dialer{}).DialContext(cctx,"tcp",net.JoinHostPort(ip.String(),strconv.Itoa(port)));cancel();if e==nil{conn.Close();open=append(open,port)}}
    if len(open)>0{mu.Lock();found=append(found,map[string]interface{}{"ip":ip.String(),"open_ports":open});mu.Unlock()}
   }(addr)
  }
  wg.Wait();return map[string]interface{}{"hosts":found,"scanned":count},nil
 default:return nil,fmt.Errorf("unsupported command %q",action)
 }
}
