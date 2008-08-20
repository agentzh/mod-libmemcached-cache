#!/usr/bin/env perl

use strict;
use warnings;

use lib '../../lib';
use utf8;
use JSON::XS;
use YAML 'Dump';
use WWW::OpenResty::Simple;
#use Date::Manip;
use Getopt::Std;

my %opts;
getopts('u:s:p:h', \%opts);
if ($opts{h}) {
    die "Usage: $0 -u <user> -p <password> -s <openresty_server>\n";
}
my $user = $opts{u} or
    die "No OpenResty account name specified via option -u\n";
my $password = $opts{p} or
    die "No OpenResty account's Admin password specified via option -p\n";
my $server = $opts{s} || 'http://api.openresty.org';

my $resty = WWW::OpenResty::Simple->new( { server => $server } );
$resty->login($user, $password);
$resty->delete("/=/role/Public/~/~");
#$resty->delete("/=/role");
$resty->delete("/=/view");
$resty->delete("/=/feed");
$resty->delete("/=/model");

$resty->post(
    '/=/model/Menu',
    {
        description => "Site menus",
        columns => [
            { name => 'name', type => 'text', label => 'Menu name (anchor)' },
            { name => 'label', type => 'text', label => 'Menu label' },
            { name => 'content', type => 'text', label => 'Menu content' },
        ],
    }
);

$resty->post(
    '/=/model/Menu/~/~',
    [
        { name => "home", label => "Home", content => <<"_EOC_" },
<img src="http://us.i1.yimg.com/us.yimg.com/lib/smb/assets/hosting/yss/themes/portland/clio/images/en-us/za_1.1.4.1.jpg"><br><br>

Private equity managers today see opportunities in vast sectors of the PRC economy that have no dominant industry leader, and in research labs that are percolating with innovations. China is one of the hottest for private equity investment.<br><br>

We are proud that we are in China, we are with Chinese during this China age. It's honorable to contribute in China's private equity industry development and help Chinese enterprises in each steps of their growths. We are looking forward to meet entrepreneurs, professionals,and bankers through this website. <br><br>

<h3>What We Do</h3>
ON Capital is a China focused opportunity fund, dedicated in minority
investments in high growth Chinese companies seeking expansion/development
capital.<br>

<br>Since inception in year 2004, ON Capital has invested
 in various industries with 3 IPOs in Hong Kong, Australia and United States, and achieve 4times of return to all investors.<br>

<br>ON Capital is aiming to create values to investors, and is focusing in opportunity investment in China Mainland.&nbsp; ON Capital believes&nbsp; that China offers an attractive environment for investing in unlisted companies for, inter alia, because of China's macro economy growth and government institutional reforms. We regards the consolidation and restructuring of enterprises in both the private and state owned sectors is providing new investment opportunities. And current China’s tightened monetary policy is generally favorable for Private Equity activities with increasing investment opportunities
_EOC_
        { name => "portfolio", label => "Portfolio", content => <<"_EOC_" },
  <div id="zWrap">
    <div id="zA">
      <div class="modWrap">
        <p>We have</p>

        <ul>
          <li>8 investments since 2004</li>

          <li>106.6% Gross IRR</li>

          <li>4.0x multiple to cost and all shareholder have
          received investment principal distribution in
          multiple</li>

          <li>Investments crystallized via IPOs (HKSE, ASX, NYSE)
          generating a realized IRR of 129.1%</li>
        </ul>

        <div class=
        "module_container module_container_zA_service_container"
        id="mcontainer_zA.1">
          <div id="header_zA.1"></div>

          <ul class="module_bd_container" id="mbdcontainer_zA.1">
            <li class="module service" id=
            "module_itemRecordGuid.48606a7abce670.98890291">
              <h3 id="mf_itemGuid.48606a7abce5e1.46966248" class=
              "modfield title editable flexContent rte_limited_a"
              rel="itemGuid.48606a7abce5e1.46966248">Turbo Speed
              (HKSE:0818.HK)</h3>

              <div id="mf_itemGuid.48606a7abce5e1.46966249" class=
              "modfield description editable flexContent rte" rel=
              "itemGuid.48606a7abce5e1.46966249">
                <ul>
                  <li>Awarded by China Mobile to be the sole
                  provider of its nationwide Interactive Voice
                  Response “IVR” platform to all service and
                  content providers seeking to be connected to
                  China Mobile</li>

                  <li>Now a subsidiary of Hi Sun Group Limited
                  (HKSE: 0818.HK), which is listed on the Hong Kong
                  Stock Exchange</li>

                  <li>Hi Sun has been operating the platform since
                  late 2003 profitably and receives 15% of all
                  revenue generated by users of all services on it
                  (payment made by China Mobile directly)</li>

                  <li>While Hi Sun covers the whole nation, all
                  competitors operate at only regional level, on a
                  province by province basis</li>

                  <li>As IVR continue to grow in China, Hi Sun has
                  huge operating leverage to expand into the rest
                  of the mobile value-added service industry, based
                  on comparison with the Korea and Japan
                  markets</li>

                  <li>ON Capital led first round funding for 16%
                  equity of Hi Sun and has disposed all of the
                  stake at 7.3X multiple return</li>
                </ul>
              </div>
            </li>

            <li class="module service" id=
            "module_itemRecordGuid.48606a7abce670.98890293">
              <h3 id="mf_itemGuid.48606a7abce5e1.46966252" class=
              "modfield title editable flexContent rte_limited_a"
              rel="itemGuid.48606a7abce5e1.46966252">Arasor
              (ASX:ARR)</h3>

              <div id="mf_itemGuid.48606a7abce5e1.46966253" class=
              "modfield description editable flexContent rte" rel=
              "itemGuid.48606a7abce5e1.46966253">
                <ul>
                  <li>Founded and managed by Dr Simon Cao, a
                  scientist in opto-electronics and labeled by
                  Forbes as 'Godfather of WDM’</li>

                  <li>Mr Cao has personally funded Arasor with
                  USD10mil+; and was previously the founder and key
                  executive of Avanex and Oplink</li>

                  <li>Solid order book from 1st tier global telecom
                  carriers and equipment vendors, with
                  exceptionally strong growth in India and
                  China</li>

                  <li>Proprietary technology platform which leads
                  to significant cost and performance
                  advantages</li>

                  <li>Arasor is currently the only company in the
                  industry which has productized an optical chip
                  set for Laser TV. As a new class of high-end
                  consumer product, Laser TV has been well endorsed
                  and signed up by a number of global consumer
                  electronic giants such as Mitsubishi and
                  Samsung</li>

                  <li>ON Capital led in early 2006 and gained 8.8%
                  equity of Arasor</li>

                  <li>IPO in Oct 2006 at ASX at around 2X of ON
                  Capital entry cost (with 2 years lock-up)</li>
                </ul>
              </div>
            </li>

            <li class="module service" id=
            "module_itemRecordGuid.48606a7abce670.98890294">
              <h3 id="mf_itemGuid.48606a7abce5e1.46966254" class=
              "modfield title editable flexContent rte_limited_a"
              rel="itemGuid.48606a7abce5e1.46966254">Gushan
              (NYSE:GU)<br></h3>

              <div id="mf_itemGuid.48606a7abce5e1.46966255" class=
              "modfield description editable flexContent rte" rel=
              "itemGuid.48606a7abce5e1.46966255">
                <ul>
                  <li>Known largest producer of Biodiesel in China
                  having influence on government’s effort in
                  promoting alternative or green fuel and in
                  setting up a national standards and
                  specifications of BioDiesel</li>

                  <li>Low competition with early mover advantage
                  (Founded in 2001)</li>

                  <li>Currently an aggregate annual production
                  capacity of 240,000 tons of biodiesel; strong
                  revenue growth</li>

                  <li>In-house R&amp;D team with proprietary
                  technologies &amp; IP rights</li>

                  <li>China being a big energy user, huge demand on
                  diesel. With the ever-growing concern over crude
                  oil price and supply, alternative fuel will
                  continue to attract more attention</li>

                  <li>Gushan went IPO in December 2007 in NYSE
                  (GU), ON Capital realized an IRR of 215% against
                  our investment cost</li>
                </ul>
              </div>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
_EOC_
    ]
);

$resty->post(
    '/=/view/MenuList',
    { definition => 'select name, label from Menu order by $order_by | id asc' }
);

$resty->post(
    '/=/role/Public/~/~',
    [
        {url => '/=/model/Menu/~/~'},
        {url => '/=/view/MenuList/~/~'},
    ]
);

print Dump($resty->get('/=/model')), "\n";

