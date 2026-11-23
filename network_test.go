package viamsystem

import (
 "context"
 "net"
 "testing"
)
func TestNetworkConfig(t *testing.T){
 for _,tc:=range []struct{c networkConfig;valid bool}{
 {networkConfig{},true},
 {networkConfig{AllowedCIDRs:[]string{"192.168.0.0/24"}},true},
 {networkConfig{AllowedCIDRs:[]string{"invalid"}},false},
 {networkConfig{MaxHosts:4097},false},
 }{_,_,err:=tc.c.Validate("");if (err==nil)!=tc.valid{t.Fatalf("config %+v: %v",tc.c,err)}}
}
func TestNetworkAllowed(t *testing.T){
 n:=&networkComponent{cfg:&networkConfig{}}
 if !n.allowed(net.ParseIP("192.168.1.5")){t.Fatal("private address rejected")}
 if n.allowed(net.ParseIP("8.8.8.8")){t.Fatal("public address accepted")}
 if n.allowed(net.ParseIP("127.0.0.1")){t.Fatal("loopback accepted")}
}
func TestNetworkCommands(t *testing.T){
 n:=&networkComponent{cfg:&networkConfig{}}
 if _,err:=n.DoCommand(context.Background(),map[string]interface{}{"command":"interfaces"});err!=nil{t.Fatal(err)}
 if _,err:=n.DoCommand(context.Background(),map[string]interface{}{"command":"scan","subnet":"8.8.8.0/24"});err==nil{t.Fatal("public scan allowed")}
}
