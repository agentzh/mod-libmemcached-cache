####################################################################
#
#    This file was generated using Parse::Yapp version 1.05.
#
#        Don't edit this file, use source file instead.
#
#             ANY CHANGE MADE HERE WILL BE LOST !
#
####################################################################
package MiniSQL::Select;
use vars qw ( @ISA );
use strict;

@ISA= qw ( Parse::Yapp::Driver );
use Parse::Yapp::Driver;

#line 5 "grammar/Select.yp"


my (
    @Models, @Columns, @OutVars,
    $InVals, %Defaults, $Quote, $QuoteIdent,
    @Unbound,
);



sub new {
        my($class)=shift;
        ref($class)
    and $class=ref($class);

    my($self)=$class->SUPER::new( yyversion => '1.05',
                                  yystates =>
[
	{#State 0
		ACTIONS => {
			"select" => 3
		},
		GOTOS => {
			'select_stmt' => 1,
			'statement' => 2,
			'miniSQL' => 4
		}
	},
	{#State 1
		ACTIONS => {
			";" => 5
		},
		DEFAULT => -3
	},
	{#State 2
		DEFAULT => -1
	},
	{#State 3
		ACTIONS => {
			"sum" => 11,
			"max" => 7,
			"*" => 13,
			'VAR' => 14,
			"count" => 15,
			'IDENT' => 8,
			"min" => 19
		},
		GOTOS => {
			'symbol' => 6,
			'proc_call' => 9,
			'qualified_symbol' => 10,
			'pattern' => 12,
			'pattern_list' => 16,
			'aggregate' => 17,
			'func' => 18,
			'column' => 20
		}
	},
	{#State 4
		ACTIONS => {
			'' => 21
		}
	},
	{#State 5
		DEFAULT => -2
	},
	{#State 6
		ACTIONS => {
			"." => 22
		},
		DEFAULT => -33
	},
	{#State 7
		DEFAULT => -18
	},
	{#State 8
		ACTIONS => {
			"(" => 23
		},
		DEFAULT => -35
	},
	{#State 9
		DEFAULT => -13
	},
	{#State 10
		DEFAULT => -32
	},
	{#State 11
		DEFAULT => -21
	},
	{#State 12
		ACTIONS => {
			"," => 24
		},
		DEFAULT => -10
	},
	{#State 13
		DEFAULT => -15
	},
	{#State 14
		ACTIONS => {
			"|" => 25
		},
		DEFAULT => -37
	},
	{#State 15
		DEFAULT => -20
	},
	{#State 16
		ACTIONS => {
			"where" => 26,
			"order by" => 31,
			"limit" => 30,
			"group by" => 34,
			"from" => 35,
			"offset" => 37
		},
		DEFAULT => -5,
		GOTOS => {
			'postfix_clause_list' => 29,
			'order_by_clause' => 28,
			'offset_clause' => 27,
			'from_clause' => 36,
			'where_clause' => 32,
			'group_by_clause' => 33,
			'limit_clause' => 38,
			'postfix_clause' => 39
		}
	},
	{#State 17
		ACTIONS => {
			'IDENT' => 41,
			'VAR' => 14
		},
		DEFAULT => -12,
		GOTOS => {
			'symbol' => 40,
			'alias' => 42
		}
	},
	{#State 18
		ACTIONS => {
			"(" => 43
		}
	},
	{#State 19
		DEFAULT => -19
	},
	{#State 20
		DEFAULT => -14
	},
	{#State 21
		DEFAULT => 0
	},
	{#State 22
		ACTIONS => {
			'VAR' => 14,
			'IDENT' => 41
		},
		GOTOS => {
			'symbol' => 44
		}
	},
	{#State 23
		ACTIONS => {
			'NUM' => 47,
			'VAR' => 49,
			'STRING' => 46
		},
		GOTOS => {
			'parameter' => 48,
			'string' => 45,
			'parameter_list' => 50
		}
	},
	{#State 24
		ACTIONS => {
			"sum" => 11,
			"max" => 7,
			"*" => 13,
			'VAR' => 14,
			"count" => 15,
			'IDENT' => 8,
			"min" => 19
		},
		GOTOS => {
			'symbol' => 6,
			'proc_call' => 9,
			'qualified_symbol' => 10,
			'pattern' => 12,
			'func' => 18,
			'aggregate' => 17,
			'pattern_list' => 51,
			'column' => 20
		}
	},
	{#State 25
		ACTIONS => {
			'IDENT' => 52
		}
	},
	{#State 26
		ACTIONS => {
			"(" => 56,
			'VAR' => 14,
			'IDENT' => 41
		},
		GOTOS => {
			'comparison' => 53,
			'symbol' => 6,
			'conjunction' => 54,
			'disjunction' => 55,
			'condition' => 58,
			'column' => 57,
			'qualified_symbol' => 10
		}
	},
	{#State 27
		DEFAULT => -45
	},
	{#State 28
		DEFAULT => -43
	},
	{#State 29
		DEFAULT => -4
	},
	{#State 30
		ACTIONS => {
			'NUM' => 59
		}
	},
	{#State 31
		ACTIONS => {
			'VAR' => 14,
			'IDENT' => 41
		},
		GOTOS => {
			'symbol' => 6,
			'order_by_objects' => 61,
			'column' => 62,
			'qualified_symbol' => 10,
			'order_by_object' => 60
		}
	},
	{#State 32
		DEFAULT => -41
	},
	{#State 33
		DEFAULT => -42
	},
	{#State 34
		ACTIONS => {
			'VAR' => 14,
			'IDENT' => 41
		},
		GOTOS => {
			'symbol' => 6,
			'column_list' => 63,
			'column' => 64,
			'qualified_symbol' => 10
		}
	},
	{#State 35
		ACTIONS => {
			'VAR' => 14,
			'IDENT' => 8
		},
		GOTOS => {
			'models' => 65,
			'symbol' => 66,
			'model' => 67,
			'proc_call' => 68
		}
	},
	{#State 36
		DEFAULT => -46
	},
	{#State 37
		ACTIONS => {
			'NUM' => 69
		}
	},
	{#State 38
		DEFAULT => -44
	},
	{#State 39
		ACTIONS => {
			"where" => 26,
			"order by" => 31,
			"limit" => 30,
			"group by" => 34,
			"from" => 35,
			"offset" => 37
		},
		DEFAULT => -40,
		GOTOS => {
			'postfix_clause_list' => 70,
			'order_by_clause' => 28,
			'offset_clause' => 27,
			'from_clause' => 36,
			'where_clause' => 32,
			'group_by_clause' => 33,
			'limit_clause' => 38,
			'postfix_clause' => 39
		}
	},
	{#State 40
		DEFAULT => -38
	},
	{#State 41
		DEFAULT => -35
	},
	{#State 42
		DEFAULT => -11
	},
	{#State 43
		ACTIONS => {
			"*" => 71,
			'VAR' => 14,
			'IDENT' => 41
		},
		GOTOS => {
			'symbol' => 6,
			'column' => 72,
			'qualified_symbol' => 10
		}
	},
	{#State 44
		DEFAULT => -34
	},
	{#State 45
		DEFAULT => -25
	},
	{#State 46
		DEFAULT => -29
	},
	{#State 47
		DEFAULT => -26
	},
	{#State 48
		ACTIONS => {
			"," => 73
		},
		DEFAULT => -24
	},
	{#State 49
		ACTIONS => {
			"|" => 74
		},
		DEFAULT => -31
	},
	{#State 50
		ACTIONS => {
			")" => 75
		}
	},
	{#State 51
		DEFAULT => -9
	},
	{#State 52
		DEFAULT => -36
	},
	{#State 53
		ACTIONS => {
			"and" => 76
		},
		DEFAULT => -54
	},
	{#State 54
		ACTIONS => {
			"or" => 77
		},
		DEFAULT => -52
	},
	{#State 55
		DEFAULT => -50
	},
	{#State 56
		ACTIONS => {
			"(" => 56,
			'VAR' => 14,
			'IDENT' => 41
		},
		GOTOS => {
			'comparison' => 53,
			'symbol' => 6,
			'conjunction' => 54,
			'disjunction' => 55,
			'condition' => 78,
			'column' => 57,
			'qualified_symbol' => 10
		}
	},
	{#State 57
		ACTIONS => {
			"<" => 79,
			"like" => 80,
			"<=" => 84,
			">" => 86,
			"<>" => 85,
			">=" => 82,
			"=" => 81
		},
		GOTOS => {
			'operator' => 83
		}
	},
	{#State 58
		DEFAULT => -49
	},
	{#State 59
		DEFAULT => -77
	},
	{#State 60
		ACTIONS => {
			"," => 87
		},
		DEFAULT => -72
	},
	{#State 61
		DEFAULT => -70
	},
	{#State 62
		ACTIONS => {
			"desc" => 88,
			"asc" => 89
		},
		DEFAULT => -74,
		GOTOS => {
			'order_by_modifier' => 90
		}
	},
	{#State 63
		DEFAULT => -67
	},
	{#State 64
		ACTIONS => {
			"," => 91
		},
		DEFAULT => -69
	},
	{#State 65
		DEFAULT => -47
	},
	{#State 66
		DEFAULT => -8
	},
	{#State 67
		ACTIONS => {
			"," => 92
		},
		DEFAULT => -7
	},
	{#State 68
		DEFAULT => -48
	},
	{#State 69
		DEFAULT => -78
	},
	{#State 70
		DEFAULT => -39
	},
	{#State 71
		ACTIONS => {
			")" => 93
		}
	},
	{#State 72
		ACTIONS => {
			")" => 94
		}
	},
	{#State 73
		ACTIONS => {
			'NUM' => 47,
			'VAR' => 49,
			'STRING' => 46
		},
		GOTOS => {
			'parameter' => 48,
			'string' => 45,
			'parameter_list' => 95
		}
	},
	{#State 74
		ACTIONS => {
			'NUM' => 98,
			'STRING' => 97
		},
		GOTOS => {
			'constant' => 96
		}
	},
	{#State 75
		DEFAULT => -22
	},
	{#State 76
		ACTIONS => {
			"(" => 56,
			'VAR' => 14,
			'IDENT' => 41
		},
		GOTOS => {
			'comparison' => 99,
			'symbol' => 6,
			'column' => 57,
			'qualified_symbol' => 10
		}
	},
	{#State 77
		ACTIONS => {
			"(" => 56,
			'VAR' => 14,
			'IDENT' => 41
		},
		GOTOS => {
			'comparison' => 53,
			'conjunction' => 100,
			'symbol' => 6,
			'column' => 57,
			'qualified_symbol' => 10
		}
	},
	{#State 78
		ACTIONS => {
			")" => 101
		}
	},
	{#State 79
		DEFAULT => -61
	},
	{#State 80
		DEFAULT => -64
	},
	{#State 81
		DEFAULT => -63
	},
	{#State 82
		DEFAULT => -59
	},
	{#State 83
		ACTIONS => {
			'NUM' => 103,
			'VAR' => 105,
			'IDENT' => 41,
			'STRING' => 46
		},
		GOTOS => {
			'literal' => 104,
			'symbol' => 6,
			'string' => 102,
			'column' => 106,
			'qualified_symbol' => 10
		}
	},
	{#State 84
		DEFAULT => -60
	},
	{#State 85
		DEFAULT => -62
	},
	{#State 86
		DEFAULT => -58
	},
	{#State 87
		ACTIONS => {
			'VAR' => 14,
			'IDENT' => 41
		},
		GOTOS => {
			'symbol' => 6,
			'order_by_objects' => 107,
			'column' => 62,
			'qualified_symbol' => 10,
			'order_by_object' => 60
		}
	},
	{#State 88
		DEFAULT => -76
	},
	{#State 89
		DEFAULT => -75
	},
	{#State 90
		DEFAULT => -73
	},
	{#State 91
		ACTIONS => {
			'VAR' => 14,
			'IDENT' => 41
		},
		GOTOS => {
			'symbol' => 6,
			'column_list' => 108,
			'column' => 64,
			'qualified_symbol' => 10
		}
	},
	{#State 92
		ACTIONS => {
			'VAR' => 14,
			'IDENT' => 41
		},
		GOTOS => {
			'models' => 109,
			'symbol' => 66,
			'model' => 67
		}
	},
	{#State 93
		DEFAULT => -17
	},
	{#State 94
		DEFAULT => -16
	},
	{#State 95
		DEFAULT => -23
	},
	{#State 96
		DEFAULT => -30
	},
	{#State 97
		DEFAULT => -27
	},
	{#State 98
		DEFAULT => -28
	},
	{#State 99
		DEFAULT => -53
	},
	{#State 100
		DEFAULT => -51
	},
	{#State 101
		DEFAULT => -57
	},
	{#State 102
		DEFAULT => -65
	},
	{#State 103
		DEFAULT => -66
	},
	{#State 104
		DEFAULT => -55
	},
	{#State 105
		ACTIONS => {
			"|" => 110,
			"." => -37
		},
		DEFAULT => -31
	},
	{#State 106
		DEFAULT => -56
	},
	{#State 107
		DEFAULT => -71
	},
	{#State 108
		DEFAULT => -68
	},
	{#State 109
		DEFAULT => -6
	},
	{#State 110
		ACTIONS => {
			'NUM' => 98,
			'IDENT' => 52,
			'STRING' => 97
		},
		GOTOS => {
			'constant' => 96
		}
	}
],
                                  yyrules  =>
[
	[#Rule 0
		 '$start', 2, undef
	],
	[#Rule 1
		 'miniSQL', 1, undef
	],
	[#Rule 2
		 'statement', 2, undef
	],
	[#Rule 3
		 'statement', 1, undef
	],
	[#Rule 4
		 'select_stmt', 3,
sub
#line 28 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 5
		 'select_stmt', 2,
sub
#line 30 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 6
		 'models', 3,
sub
#line 34 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 7
		 'models', 1, undef
	],
	[#Rule 8
		 'model', 1,
sub
#line 38 "grammar/Select.yp"
{ push @Models, $_[1]; $QuoteIdent->($_[1]) }
	],
	[#Rule 9
		 'pattern_list', 3,
sub
#line 42 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 10
		 'pattern_list', 1, undef
	],
	[#Rule 11
		 'pattern', 2, undef
	],
	[#Rule 12
		 'pattern', 1, undef
	],
	[#Rule 13
		 'pattern', 1, undef
	],
	[#Rule 14
		 'pattern', 1, undef
	],
	[#Rule 15
		 'pattern', 1, undef
	],
	[#Rule 16
		 'aggregate', 4,
sub
#line 54 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 17
		 'aggregate', 4,
sub
#line 56 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 18
		 'func', 1, undef
	],
	[#Rule 19
		 'func', 1, undef
	],
	[#Rule 20
		 'func', 1, undef
	],
	[#Rule 21
		 'func', 1, undef
	],
	[#Rule 22
		 'proc_call', 4,
sub
#line 66 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 23
		 'parameter_list', 3,
sub
#line 70 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 24
		 'parameter_list', 1, undef
	],
	[#Rule 25
		 'parameter', 1, undef
	],
	[#Rule 26
		 'parameter', 1, undef
	],
	[#Rule 27
		 'constant', 1, undef
	],
	[#Rule 28
		 'constant', 1, undef
	],
	[#Rule 29
		 'string', 1,
sub
#line 80 "grammar/Select.yp"
{ $Quote->(parse_string($_[1])) }
	],
	[#Rule 30
		 'string', 3,
sub
#line 82 "grammar/Select.yp"
{ push @OutVars, $_[1];
            my $val = $InVals->{$_[1]};
            if (!defined $val) {
                my $default;
                $Defaults{$_[1]} = $default = parse_string($_[3]);
                return $Quote->($default);
            }
            $Quote->($val);
          }
	],
	[#Rule 31
		 'string', 1,
sub
#line 92 "grammar/Select.yp"
{ push @OutVars, $_[1];
            my $val = $InVals->{$_[1]};
            if (!defined $val) {
                push @Unbound, $_[1];
                return $Quote->("");
            }
            $Quote->($val);
          }
	],
	[#Rule 32
		 'column', 1, undef
	],
	[#Rule 33
		 'column', 1,
sub
#line 103 "grammar/Select.yp"
{ push @Columns, $_[1]; $QuoteIdent->($_[1]) }
	],
	[#Rule 34
		 'qualified_symbol', 3,
sub
#line 107 "grammar/Select.yp"
{
                      push @Models, $_[1];
                      push @Columns, $_[3];
                      $QuoteIdent->($_[1]).'.'.$QuoteIdent->($_[3]);
                    }
	],
	[#Rule 35
		 'symbol', 1, undef
	],
	[#Rule 36
		 'symbol', 3,
sub
#line 116 "grammar/Select.yp"
{ push @OutVars, $_[1];
            my $val = $InVals->{$_[1]};
            if (!defined $val) {
                my $default;
                $Defaults{$_[1]} = $default = $_[3];
                _IDENT($default) or die "Bad symbol: $default\n";
                return $default;
            }
            _IDENT($val) or die "Bad symbol: $val\n";
            $val;
          }
	],
	[#Rule 37
		 'symbol', 1,
sub
#line 128 "grammar/Select.yp"
{ push @OutVars, $_[1];
            my $val = $InVals->{$_[1]};
            if (!defined $val) {
                push @Unbound, $_[1];
                return '';
            }
            #warn _IDENT($val);
            _IDENT($val) or die "Bad symbol: $val\n";
            $val;
          }
	],
	[#Rule 38
		 'alias', 1, undef
	],
	[#Rule 39
		 'postfix_clause_list', 2,
sub
#line 144 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 40
		 'postfix_clause_list', 1, undef
	],
	[#Rule 41
		 'postfix_clause', 1, undef
	],
	[#Rule 42
		 'postfix_clause', 1, undef
	],
	[#Rule 43
		 'postfix_clause', 1, undef
	],
	[#Rule 44
		 'postfix_clause', 1, undef
	],
	[#Rule 45
		 'postfix_clause', 1, undef
	],
	[#Rule 46
		 'postfix_clause', 1, undef
	],
	[#Rule 47
		 'from_clause', 2,
sub
#line 157 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 48
		 'from_clause', 2,
sub
#line 159 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 49
		 'where_clause', 2,
sub
#line 163 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 50
		 'condition', 1, undef
	],
	[#Rule 51
		 'disjunction', 3,
sub
#line 170 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 52
		 'disjunction', 1, undef
	],
	[#Rule 53
		 'conjunction', 3,
sub
#line 175 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 54
		 'conjunction', 1, undef
	],
	[#Rule 55
		 'comparison', 3,
sub
#line 180 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 56
		 'comparison', 3,
sub
#line 182 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 57
		 'comparison', 3,
sub
#line 184 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 58
		 'operator', 1, undef
	],
	[#Rule 59
		 'operator', 1, undef
	],
	[#Rule 60
		 'operator', 1, undef
	],
	[#Rule 61
		 'operator', 1, undef
	],
	[#Rule 62
		 'operator', 1, undef
	],
	[#Rule 63
		 'operator', 1, undef
	],
	[#Rule 64
		 'operator', 1, undef
	],
	[#Rule 65
		 'literal', 1, undef
	],
	[#Rule 66
		 'literal', 1, undef
	],
	[#Rule 67
		 'group_by_clause', 2,
sub
#line 201 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 68
		 'column_list', 3,
sub
#line 205 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 69
		 'column_list', 1, undef
	],
	[#Rule 70
		 'order_by_clause', 2,
sub
#line 210 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 71
		 'order_by_objects', 3,
sub
#line 214 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 72
		 'order_by_objects', 1, undef
	],
	[#Rule 73
		 'order_by_object', 2,
sub
#line 219 "grammar/Select.yp"
{ join(' ', @_[1..$#_]) }
	],
	[#Rule 74
		 'order_by_object', 1, undef
	],
	[#Rule 75
		 'order_by_modifier', 1, undef
	],
	[#Rule 76
		 'order_by_modifier', 1, undef
	],
	[#Rule 77
		 'limit_clause', 2,
sub
#line 227 "grammar/Select.yp"
{ delete $_[0]->YYData->{limit}; join(' ', @_[1..$#_]) }
	],
	[#Rule 78
		 'offset_clause', 2,
sub
#line 230 "grammar/Select.yp"
{
                 delete $_[0]->YYData->{offset}; join(' ', @_[1..$#_]) }
	]
],
                                  @_);
    bless($self,$class);
}

#line 234 "grammar/Select.yp"


#use Smart::Comments;

sub _Error {
    my ($value) = $_[0]->YYCurval;

    my $token = 1;
    ## $value
    my @expect = $_[0]->YYExpect;
    ### expect: @expect
    my ($what) = $value ? "input: \"$value\"" : "end of input";

    map { $_ = "'$_'" if $_ ne '' and !/^\w+$/ } @expect;
    my $expected = join " or ", @expect;
    _SyntaxError(1, "Unexpected $what".($expected?" ($expected expected)":''), $.);
}

sub _SyntaxError {
    my ($level, $message, $lineno) = @_;

    $message= "line $lineno: error: $message";
    die $message, ".\n";
}

sub _Lexer {
    my ($parser) = shift;

    my $yydata = $parser->YYData;
    my $source = $yydata->{source};
    #local $" = "\n";
    defined $yydata->{input} && $yydata->{input} =~ s/^\s+//s;

    if (!defined $yydata->{input} || $yydata->{input} eq '') {
        ### HERE!!!
        $yydata->{input} = <$source>;
    }
    if (!defined $yydata->{input}) {
        return ('', undef);
    }

    ## other data: <$source>
    ### data: $yydata->{input}
    ### lineno: $.

    for ($yydata->{input}) {
        s/^\s*(\d+(?:\.\d+)?)\b//s
                and return ('NUM', $1);
        s/^\s*('(?:\\.|''|[^'])*')//
                and return ('STRING', $1);
        s/^\s*"(\w*)"//
                and return ('IDENT', $1);
        s/^\s*(\$(\w*)\$.*?\$\2\$)//
                and return ('STRING', $1);
        s/^\s*(\*|count|sum|max|min|select|and|or|from|where|delete|update|set|order by|asc|desc|group by|limit|offset)\b//is
                and return (lc($1), lc($1));
        s/^\s*(<=|>=|<>)//s
                and return ($1, $1);
        s/^\s*([A-Za-z][A-Za-z0-9_]*)\b//s
                and return ('IDENT', $1);
        s/^\$(\w+)//s
                and return ('VAR', $1);
        s/^\s*(\S)//s
                and return ($1, $1);
    }
}

sub parse_string {
    my $s = $_[0];
    if ($s =~ /^'(.*)'$/) {
        $s = $1;
        $s =~ s/''/'/g;
        $s =~ s/\\n/\n/g;
        $s =~ s/\\t/\t/g;
        $s =~ s/\\r/\r/g;
        $s =~ s/\\(.)/$1/g;
        return $s;
    } elsif ($s =~ /^\$(\w*)\$(.*)\$\1\$$/) {
        $s = $2;
        return $s;
    } elsif ($s =~ /^[\d\.]*$/) {
        return $s;
    } else {
        die "Unknown string literal: $s";
    }
}

sub parse {
    my ($self, $sql, $params) = @_;
    open my $source, '<', \$sql;
    my $yydata = $self->YYData;
    $yydata->{source} = $source;
    $yydata->{limit} = $params->{limit};
    $yydata->{offset} = $params->{offset};

    $Quote = $params->{quote} || sub { "''" };
    $QuoteIdent = $params->{quote_ident} || sub { '""' };
    $InVals = $params->{vars} || {};
    #$QuoteIdent = $params->{quote_ident};

    #$self->YYData->{INPUT} = ;
    ### $sql
    @Unbound = ();
    @Models = ();
    @Columns = ();
    @OutVars = ();
    %Defaults = ();
    my $sql = $self->YYParse( yydebug => 0 & 0x1F, yylex => \&_Lexer, yyerror => \&_Error );
    close $source;
    return {
        limit   => $yydata->{limit},
        offset  => $yydata->{offset},
        models  => [@Models],
        columns => [@Columns],
        sql => $sql,
        vars => [@OutVars],
        defaults => {%Defaults},
        unbound => [@Unbound],
    };
}

sub _IDENT {
    (defined $_[0] && $_[0] =~ /^[A-Za-z]\w*$/) ? $_[0] : undef;
}

#my ($select) =new Select;
#my $var = $select->Run;

1;


1;
