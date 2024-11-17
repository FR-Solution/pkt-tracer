package flags

import (
	"reflect"
	"regexp"
	"time"

	model "github.com/wildberries-tech/pkt-tracer/internal/models/trace"
	ch "github.com/wildberries-tech/pkt-tracer/internal/registry/clickhouse"
	"github.com/wildberries-tech/pkt-tracer/pkg/meta"

	"github.com/go-faster/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	flagNameTag     = "name"
	flagShortcutTag = "key"
	flagUsageTag    = "usage"
	flagExampleTag  = "eg"
	groupFlagTag    = "gr"
)

var validateFilterFlags = regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*_.+\-_:<>~/?-]+$`)

type (
	SliceT interface {
		~uint |
			~uint64 |
			~uint32 |
			~uint16 |
			~uint8 |
			~int |
			~int64 |
			~int32 |
			~int16 |
			~int8
	}

	FlagParams struct {
		Name     string
		Key      string
		DefValue any
		Usage    string
		Example  string
		Group    string
	}

	Flags struct {
		// path to config file
		ConfigPath string `name:"config" key:"c" usage:"app config file"`
		// output in json format
		JsonFormat bool `name:"json" key:"j" usage:"enable extended output in the json format"`
		// trace hub server url
		ServerUrl string `name:"host" key:"H" usage:"trace-hub service address (format: <IP>:<port>)" eg:"tcp://127.0.0.1:9000"`
		// level of log
		LogLevel string `name:"log-level" usage:"log level: INFO|DEBUG|WARN|ERROR|PANIC|FATAL"`
		// verbose output mode
		VerboseMode bool `name:"verbose" key:"v" usage:"verbose output mode"`
		// time filter
		TimeFrom *time.Time `name:"time-from" usage:"specifies the start time of the time interval in the format '2024-10-08T12:30:00Z'"`
		// time filter
		TimeTo *time.Time `name:"time-to" usage:"specifies the end time of the time interval in the format '2024-10-08T12:30:00Z'"`
		// time filter
		TimeDuration *time.Duration `name:"time" key:"t" usage:"time offset from current time (e.g., 1s for 1 second, 1m for 1 minute, 1h for 1 hour, 1d for 1 day)" eg:"1s"`
		// follow mode on/off
		FollowMode bool `name:"follow" key:"f" usage:"follow or tail continuous output [Required --time Flag]"`
		// complex query filter parameter
		Query string `name:"query" key:"q" usage:"complex query filter like: (sport>=80 and sport<=443) and ip-dst=='93.184.215.14' and dport not in (80,443)" eg:"(sport>=80 and sport<=443) and ip-dst=='93.184.215.14' and dport in (80,443)"`
		// traces ids
		TrId []uint `name:"trid" gr:"trace" usage:"set filter by trace id. Supported multiple values separated by symbol ',' and meaning logical OR operation (e.g. --trid 123,987,234)" eg:"123,987,234"`
		// nftables tables names
		Table []string `name:"table" gr:"trace" usage:"set filter by table name. Supported multiple values separated by symbol ',' and meaning logical OR operation (e.g. --table flt,fwd,output)" eg:"flt,fwd,output"`
		// nftables chains names
		Chain []string `name:"chain" gr:"trace" usage:"set filter by chain name. Supported multiple values (see --table Flag)" eg:"chain1,chain2"`
		// nftables jump to a target names
		JumpTarget []string `name:"jt" gr:"trace" usage:"set filter by jump target name. Supported multiple values (see --table Flag)" eg:"target1,target2"`
		// nftables rules numbers
		RuleHandle []uint `name:"handle" gr:"trace" usage:"set filter by rule handle. Supported multiple values (see --trid Flag)" eg:"1,2,3,4,5"`
		// protocols family
		Family []string `name:"family" gr:"trace" usage:"set filter by protocols family (ip/ip6). Supported multiple values (see --table Flag)" eg:"ip,ip6"`
		// input network interfaces
		Iifname []string `name:"iif" gr:"trace" usage:"set filter by network interface name for ingress traffic. Supported multiple values (see --table Flag)" eg:"eth0,eth1"`
		// output network interfaces
		Oifname []string `name:"oif" gr:"trace" usage:"set filter by network interface name for egress traffic. Supported multiple values (see --table Flag)" eg:"eth0,eth1"`
		// source mac addresses
		SMacAddr []string `name:"hw-src" gr:"trace" usage:"set filter by source mac address. Supported multiple values (see --table Flag)" eg:"00:00:00:00:00:00,00:00:00:00:00:01"`
		// destination mac addresses
		DMacAddr []string `name:"hw-dst" gr:"trace" usage:"set filter by destination mac address. Supported multiple values (see --table Flag)" eg:"00:00:00:00:00:00,00:00:00:00:00:01"`
		// source ip addresses
		SAddr []string `name:"ip-src" gr:"trace" usage:"set filter by source ip address. Supported multiple values (see --table Flag)" eg:"192.168.0.1,192.168.0.2"`
		// destination ip addresses
		DAddr []string `name:"ip-dst" gr:"trace" usage:"set filter by destination ip address. Supported multiple values (see --table Flag)" eg:"192.168.0.1,192.168.0.2"`
		// source ports
		SPort []uint `name:"sport" gr:"trace" usage:"set filter by source port. Supported multiple values (see --trid Flag)" eg:"80,443"`
		// destination ports
		DPort []uint `name:"dport" gr:"trace" usage:"set filter by destination port. Supported multiple values (see --trid Flag)" eg:"80,443"`
		// names of the security group for src ip
		SSgName []string `name:"sg-src" gr:"trace" usage:"set filter by source security group name. Supported multiple values (see --table Flag)" eg:"sg1,sg2"`
		// names of the security group for dst ip
		DSgName []string `name:"sg-dst" gr:"trace" usage:"set filter by destination security group name. Supported multiple values (see --table Flag)" eg:"sg1,sg2"`
		// names of the network for src ip
		SSgNet []string `name:"net-src" gr:"trace" usage:"set filter by source network name. Supported multiple values (see --table Flag)" eg:"192.168.0.0/32,192.168.50.0/32"`
		// names of the network for dst ip
		DSgNet []string `name:"net-dst" gr:"trace" usage:"set filter by destination network name. Supported multiple values (see --table Flag)" eg:"192.168.0.0/32,192.168.50.0/32"`
		// lengths of packets
		Length []uint `name:"len" gr:"trace" usage:"set filter by network packet length. Supported multiple values (see --trid Flag)" eg:"20,80"`
		// ip protocols (tcp/udp/icmp/...)
		IpProto []string `name:"proto" gr:"trace" usage:"set filter by ip protocol (tcp/udp/icmp/...). Supported multiple values (see --table Flag)" eg:"tcp,udp,icmp"`
		// verdicts of rules
		Verdict []string `name:"verdict" gr:"trace" usage:"set filter by rule verdict (accept/drop/continue). Supported multiple values (see --table Flag)" eg:"accept,drop,continue"`
		// visor agents identifier
		AgentsIds []string `name:"agent-id" usage:"set filter by visor agents id Supported multiple values (see --table Flag)" eg:"tracer1,tracer2"`
	}

	QueryFlag string

	attachOptions interface {
		isAttachOptions()
	}
	WithExcludeFlags struct {
		attachOptions
		ExcludeFlags []string
	}
	WithDefValues struct {
		attachOptions
		Defvalues map[string]any
	}
	WithPersistentFlags struct {
		attachOptions
		Pflags map[string]*pflag.FlagSet
	}
)

func (q QueryFlag) ToSql() (ret string, err error) {
	if q == "" {
		return
	}
	obj := &ch.TraceDB{}
	f := Flags{}
	return NewQueryParser(string(q), map[string]string{
		f.NameFromTag(&f.TrId):       obj.FieldTag(&obj.TrId),
		f.NameFromTag(&f.Table):      obj.FieldTag(&obj.Table),
		f.NameFromTag(&f.Chain):      obj.FieldTag(&obj.Chain),
		f.NameFromTag(&f.JumpTarget): obj.FieldTag(&obj.JumpTarget),
		f.NameFromTag(&f.RuleHandle): obj.FieldTag(&obj.RuleHandle),
		f.NameFromTag(&f.Family):     obj.FieldTag(&obj.Family),
		f.NameFromTag(&f.Iifname):    obj.FieldTag(&obj.Iifname),
		f.NameFromTag(&f.Oifname):    obj.FieldTag(&obj.Oifname),
		f.NameFromTag(&f.SMacAddr):   obj.FieldTag(&obj.SMacAddr),
		f.NameFromTag(&f.DMacAddr):   obj.FieldTag(&obj.DMacAddr),
		f.NameFromTag(&f.SAddr):      obj.FieldTag(&obj.SAddr),
		f.NameFromTag(&f.DAddr):      obj.FieldTag(&obj.DAddr),
		f.NameFromTag(&f.SPort):      obj.FieldTag(&obj.SPort),
		f.NameFromTag(&f.DPort):      obj.FieldTag(&obj.DPort),
		f.NameFromTag(&f.SSgName):    obj.FieldTag(&obj.SSgName),
		f.NameFromTag(&f.DSgName):    obj.FieldTag(&obj.DSgName),
		f.NameFromTag(&f.SSgNet):     obj.FieldTag(&obj.SSgNet),
		f.NameFromTag(&f.DSgNet):     obj.FieldTag(&obj.DSgNet),
		f.NameFromTag(&f.Length):     obj.FieldTag(&obj.Length),
		f.NameFromTag(&f.IpProto):    obj.FieldTag(&obj.IpProto),
		f.NameFromTag(&f.Verdict):    obj.FieldTag(&obj.Verdict),
	}).ToSql()
}

func (f Flags) Clone(fn func(f *Flags)) {
	fn(&f)
}

func (f *Flags) NameFromTag(fieldPtr any) string {
	return meta.GetFieldTag(f, fieldPtr, flagNameTag)
}

func (f *Flags) GetFieldFlagParams(fieldPtr any) FlagParams {
	defValuesMap := map[string]any{
		f.NameFromTag(&f.LogLevel): "INFO",
	}
	list := meta.ListFieldTags(f, fieldPtr, flagNameTag, flagShortcutTag, flagUsageTag, flagExampleTag, groupFlagTag)
	return FlagParams{
		Name:     list[flagNameTag],
		Key:      list[flagShortcutTag],
		DefValue: defValuesMap[list[flagNameTag]],
		Usage:    list[flagUsageTag],
		Example:  list[flagExampleTag],
		Group:    list[groupFlagTag],
	}
}

func (f *Flags) GetFlagParamsByGroup(group string) (ret []FlagParams) {
	tagNames := []string{flagNameTag, flagShortcutTag, flagUsageTag, flagExampleTag, groupFlagTag}
	meta.IterFieldsTags(f, tagNames, func(field any, tag map[string]string, offset uintptr) {
		if tag[groupFlagTag] == group {
			ret = append(ret, FlagParams{
				Name:    tag[flagNameTag],
				Key:     tag[flagShortcutTag],
				Usage:   tag[flagUsageTag],
				Example: tag[flagExampleTag],
				Group:   tag[groupFlagTag],
			})
		}
	})
	return
}

func (f *Flags) ToTraceScopeModel() (md model.TraceScopeModel, err error) {
	sqlQuery, err := QueryFlag(f.Query).ToSql()
	if err != nil {
		return md, err
	}
	var timeRange *model.TimeRange
	if f.TimeFrom != nil && f.TimeTo != nil {
		timeRange = &model.TimeRange{
			From: *f.TimeFrom,
			To:   *f.TimeTo,
		}
	} else if f.TimeDuration != nil {
		currTime := time.Now()
		timeRange = &model.TimeRange{
			From: currTime.Add(-*f.TimeDuration),
			To:   currTime,
		}
	}

	md = model.TraceScopeModel{
		TrId:       castSlice[uint, uint32](f.TrId),
		Table:      f.Table,
		Chain:      f.Chain,
		JumpTarget: f.JumpTarget,
		RuleHandle: castSlice[uint, uint64](f.RuleHandle),
		Family:     f.Family,
		Iifname:    f.Iifname,
		Oifname:    f.Oifname,
		SMacAddr:   f.SMacAddr,
		DMacAddr:   f.DMacAddr,
		SAddr:      f.SAddr,
		DAddr:      f.DAddr,
		SPort:      castSlice[uint, uint32](f.SPort),
		DPort:      castSlice[uint, uint32](f.DPort),
		SSgName:    f.SSgName,
		DSgName:    f.DSgName,
		SSgNet:     f.SSgNet,
		DSgNet:     f.DSgNet,
		Length:     castSlice[uint, uint32](f.Length),
		IpProto:    f.IpProto,
		Verdict:    f.Verdict,
		Time:       timeRange,
		AgentsIds:  f.AgentsIds,
		FollowMode: f.FollowMode,
		Query:      sqlQuery,
	}

	return md, err
}

func (f *Flags) InitFromCmd(cmd *cobra.Command) (err error) {
	var flagSet *pflag.FlagSet

	v := reflect.Indirect(reflect.ValueOf(f))
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)
		flagName := field.Tag.Get(flagNameTag)
		if flagName == "" {
			return errors.Errorf("not specified tags for field: '%s'", field.Name)
		}
		flagSet = GetFlagSet(flagName, cmd)
		if flagSet == nil {
			continue
		}

		if fieldValue.CanInterface() {
			val, err := GetFlagValues(flagName, flagSet, fieldValue.Interface())
			if err != nil {
				return err
			}
			if val != nil {
				fieldValue.Set(reflect.ValueOf(val))
			}
		}
	}
	return nil
}

// Attach - attach flags to command
func (f *Flags) Attach(cmd *cobra.Command, opts ...attachOptions) (err error) {
	var (
		excludeFlags    = make(map[string]struct{})
		persistentFlags = make(map[string]*pflag.FlagSet)
		defValues       = make(map[string]any)
	)
	for _, o := range opts {
		switch t := o.(type) {
		case WithExcludeFlags:
			for _, excludeFlag := range t.ExcludeFlags {
				excludeFlags[excludeFlag] = struct{}{}
			}
		case WithPersistentFlags:
			persistentFlags = t.Pflags
		case WithDefValues:
			defValues = t.Defvalues
		}
	}

	v := reflect.Indirect(reflect.ValueOf(f))
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)
		tags := map[string]string{
			flagNameTag:     field.Tag.Get(flagNameTag),
			flagShortcutTag: field.Tag.Get(flagShortcutTag),
			flagUsageTag:    field.Tag.Get(flagUsageTag),
			flagExampleTag:  field.Tag.Get(flagExampleTag),
			groupFlagTag:    field.Tag.Get(groupFlagTag),
		}

		if tags[flagNameTag] == "" {
			return errors.Errorf("not specified tag: '%s' for field: '%s'", flagNameTag, field.Name)
		}
		flagSet, ok := persistentFlags[tags[flagNameTag]]
		if !ok {
			flagSet = cmd.Flags()
		}
		if _, ok := excludeFlags[tags[flagNameTag]]; ok {
			continue
		}
		if fieldValue.CanInterface() {
			err = SetFlag(flagSet, FlagParams{
				Name:     tags[flagNameTag],
				Key:      tags[flagShortcutTag],
				DefValue: defValues[tags[flagNameTag]],
				Usage:    tags[flagUsageTag],
				Example:  tags[flagExampleTag],
				Group:    tags[groupFlagTag],
			}, fieldValue.Interface())
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Action - execute commands according to flags
func (f *Flags) Action(cmd *cobra.Command) (err error) {
	err = f.InitFromCmd(cmd)
	if err != nil {
		return err
	}
	if f.VerboseMode {
		f.LogLevel = "DEBUG"
		flSet := GetFlagSet(f.NameFromTag(&f.LogLevel), cmd)
		if flSet == nil {
			err = errors.Errorf("flag '%s' was not setup", f.NameFromTag(&f.LogLevel))
		} else {
			err = flSet.Set(f.NameFromTag(&f.LogLevel), f.LogLevel)
		}
	}
	return
}

// Helpers...

// GetFlagSet -
func GetFlagSet(flagName string, cmd *cobra.Command) *pflag.FlagSet {
	if cmd.Flags().Lookup(flagName) != nil {
		return cmd.Flags()
	} else if cmd.PersistentFlags().Lookup(flagName) != nil {
		return cmd.PersistentFlags()
	}
	return nil
}

// GetFlagValuesT - return typed flag value by name
func GetFlagValuesT[T any](flagName string, flag *pflag.FlagSet, Type T) (ret T, err error) {
	var val any
	val, err = GetFlagValues(flagName, flag, Type)
	return val.(T), err
}

// GetFlagValues - return flag value by name
func GetFlagValues(flagName string, flag *pflag.FlagSet, Type any) (ret any, err error) {
	if !flag.Changed(flagName) {
		return ret, err
	}

	t := reflect.TypeOf(Type)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Slice:
		et := t.Elem()
		switch et.Kind() {
		case reflect.Bool:
			ret, err = flag.GetBoolSlice(flagName)
		case reflect.String:
			ret, err = flag.GetStringSlice(flagName)
			if err == nil {
				err = ValidateStringValues(ret.([]string))
			}
		case reflect.Uint:
			ret, err = flag.GetUintSlice(flagName)
		case reflect.Int:
			ret, err = flag.GetIntSlice(flagName)
		case reflect.Int32:
			ret, err = flag.GetInt32Slice(flagName)
		case reflect.Int64:
			ret, err = flag.GetInt64Slice(flagName)
		}
	case reflect.Bool:
		ret, err = flag.GetBool(flagName)
	case reflect.String:
		ret, err = flag.GetString(flagName)
	case reflect.Uint8:
		ret, err = flag.GetUint8(flagName)
	case reflect.Uint16:
		ret, err = flag.GetUint16(flagName)
	case reflect.Uint32:
		ret, err = flag.GetUint32(flagName)
	case reflect.Uint64:
		ret, err = flag.GetUint64(flagName)
	case reflect.Uint:
		ret, err = flag.GetUint(flagName)
	case reflect.Int8:
		ret, err = flag.GetInt8(flagName)
	case reflect.Int16:
		ret, err = flag.GetInt16(flagName)
	case reflect.Int32:
		ret, err = flag.GetInt32(flagName)
	case reflect.Int64:
		if t == reflect.TypeOf(time.Duration(0)) {
			ret, err = flag.GetDuration(flagName)
		} else {
			ret, err = flag.GetInt64(flagName)
		}
	case reflect.Int:
		ret, err = flag.GetInt(flagName)
	case reflect.Struct:
		if t == reflect.TypeOf(time.Time{}) {
			ret, err = flag.GetString(flagName)
			layout := "2006-01-02T15:04:05Z"
			if err != nil {
				return ret, err
			}
			ret, err = time.Parse(layout, ret.(string))
		}
	default:
		err = errors.Errorf("Visor/GetFlagValues unsupported type: '%T'", Type)
	}

	if reflect.TypeOf(Type).Kind() == reflect.Ptr {
		ptr := reflect.New(t)
		ptr.Elem().Set(reflect.ValueOf(ret))
		ret = ptr.Interface()
	}

	return ret, err
}

func SetFlagT[T any](fl *pflag.FlagSet, p FlagParams, Type T) (err error) {
	return SetFlag(fl, p, Type)
}

//nolint:gocyclo
func SetFlag(fl *pflag.FlagSet, p FlagParams, Type any) (err error) {
	if fl.Lookup(p.Name) != nil {
		return nil
	}
	t := reflect.TypeOf(Type)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Slice:
		et := t.Elem()
		switch et.Kind() {
		case reflect.Bool:
			defVal, _ := p.DefValue.([]bool)
			if p.Key != "" {
				fl.BoolSliceP(p.Name, p.Key, defVal, p.Usage)
			} else {
				fl.BoolSlice(p.Name, defVal, p.Usage)
			}
		case reflect.String:
			defVal, _ := p.DefValue.([]string)
			if p.Key != "" {
				fl.StringSliceP(p.Name, p.Key, defVal, p.Usage)
			} else {
				fl.StringSlice(p.Name, defVal, p.Usage)
			}
		case reflect.Uint:
			defVal, _ := p.DefValue.([]uint)
			if p.Key != "" {
				fl.UintSliceP(p.Name, p.Key, defVal, p.Usage)
			} else {
				fl.UintSlice(p.Name, defVal, p.Usage)
			}
		case reflect.Int:
			defVal, _ := p.DefValue.([]int)
			if p.Key != "" {
				fl.IntSliceP(p.Name, p.Key, defVal, p.Usage)
			} else {
				fl.IntSlice(p.Name, defVal, p.Usage)
			}
		case reflect.Int32:
			defVal, _ := p.DefValue.([]int32)
			if p.Key != "" {
				fl.Int32SliceP(p.Name, p.Key, defVal, p.Usage)
			} else {
				fl.Int32Slice(p.Name, defVal, p.Usage)
			}
		case reflect.Int64:
			defVal, _ := p.DefValue.([]int64)
			if p.Key != "" {
				fl.Int64SliceP(p.Name, p.Key, defVal, p.Usage)
			} else {
				fl.Int64Slice(p.Name, defVal, p.Usage)
			}
		}
	case reflect.Bool:
		defVal, _ := p.DefValue.(bool)
		if p.Key != "" {
			fl.BoolP(p.Name, p.Key, defVal, p.Usage)
		} else {
			fl.Bool(p.Name, defVal, p.Usage)
		}
	case reflect.String:
		defVal, _ := p.DefValue.(string)
		if p.Key != "" {
			fl.StringP(p.Name, p.Key, defVal, p.Usage)
		} else {
			fl.String(p.Name, defVal, p.Usage)
		}
	case reflect.Uint8:
		defVal, _ := p.DefValue.(uint8)
		if p.Key != "" {
			fl.Uint8P(p.Name, p.Key, defVal, p.Usage)
		} else {
			fl.Uint8(p.Name, defVal, p.Usage)
		}
	case reflect.Uint16:
		defVal, _ := p.DefValue.(uint16)
		if p.Key != "" {
			fl.Uint16P(p.Name, p.Key, defVal, p.Usage)
		} else {
			fl.Uint16(p.Name, defVal, p.Usage)
		}
	case reflect.Uint32:
		defVal, _ := p.DefValue.(uint32)
		if p.Key != "" {
			fl.Uint32P(p.Name, p.Key, defVal, p.Usage)
		} else {
			fl.Uint32(p.Name, defVal, p.Usage)
		}
	case reflect.Uint64:
		defVal, _ := p.DefValue.(uint64)
		if p.Key != "" {
			fl.Uint64P(p.Name, p.Key, defVal, p.Usage)
		} else {
			fl.Uint64(p.Name, defVal, p.Usage)
		}
	case reflect.Uint:
		defVal, _ := p.DefValue.(uint)
		if p.Key != "" {
			fl.UintP(p.Name, p.Key, defVal, p.Usage)
		} else {
			fl.Uint(p.Name, defVal, p.Usage)
		}
	case reflect.Int8:
		defVal, _ := p.DefValue.(int8)
		if p.Key != "" {
			fl.Int8P(p.Name, p.Key, defVal, p.Usage)
		} else {
			fl.Int8(p.Name, defVal, p.Usage)
		}
	case reflect.Int16:
		defVal, _ := p.DefValue.(int16)
		if p.Key != "" {
			fl.Int16P(p.Name, p.Key, defVal, p.Usage)
		} else {
			fl.Int16(p.Name, defVal, p.Usage)
		}
	case reflect.Int32:
		defVal, _ := p.DefValue.(int32)
		if p.Key != "" {
			fl.Int32P(p.Name, p.Key, defVal, p.Usage)
		} else {
			fl.Int32(p.Name, defVal, p.Usage)
		}
	case reflect.Int64:
		defVal, _ := p.DefValue.(int64)
		if t == reflect.TypeOf(time.Duration(0)) {
			defVal, _ := p.DefValue.(time.Duration)
			if p.Key != "" {
				fl.DurationP(p.Name, p.Key, defVal, p.Usage)
			} else {
				fl.Duration(p.Name, defVal, p.Usage)
			}
		} else {
			if p.Key != "" {
				fl.Int64P(p.Name, p.Key, defVal, p.Usage)
			} else {
				fl.Int64(p.Name, defVal, p.Usage)
			}
		}

	case reflect.Int:
		defVal, _ := p.DefValue.(int)
		if p.Key != "" {
			fl.IntP(p.Name, p.Key, defVal, p.Usage)
		} else {
			fl.Int(p.Name, defVal, p.Usage)
		}
	case reflect.Struct:
		if t == reflect.TypeOf(time.Time{}) {
			defVal, _ := p.DefValue.(string)
			if p.Key != "" {
				fl.StringP(p.Name, p.Key, defVal, p.Usage)
			} else {
				fl.String(p.Name, defVal, p.Usage)
			}
		}
	default:
		err = errors.Errorf("Visor/SetFlag unsupported type: '%T'", Type)
	}
	return err
}

func castSlice[F, T SliceT](val []F) (ret []T) {
	for i := range val {
		ret = append(ret, (T)(val[i]))
	}
	return
}

func ValidateStringValues(vals []string) error {
	for _, val := range vals {
		if err := ValidateStringValue(val); err != nil {
			return err
		}
	}
	return nil
}

func ValidateStringValue(val string) (err error) {
	if !validateFilterFlags.MatchString(val) {
		err = errors.Errorf("Flag value '%s' contains invalid characters", val)
	}
	return
}
