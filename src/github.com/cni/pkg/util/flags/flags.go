package flags

import (
	"flag"
	"github.com/spf13/pflag"
	"k8s.io/klog"
	"strings"
)

func WordSepNormalizeFunc(f *pflag.FlagSet, name string) pflag.NormalizedName {
	if strings.Contains(name, "_") {
		return pflag.NormalizedName(strings.Replace(name, "_", "-", -1))
	}
	return pflag.NormalizedName(name)
}
func InitFlags() {
	pflag.CommandLine.SetNormalizeFunc(WordSepNormalizeFunc)
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

}
func PrintFlags(flags *pflag.FlagSet) {
	flags.VisitAll(func(f *pflag.Flag) {
		klog.V(1).Infof("FLAG: --%s=%q", f.Name, f.Value)
	})
}
