require 'digest/sha1'
require 'openssl'
require 'zip/zip'
require 'base64'
require 'open-uri'

module Passbook
  class PKPass

    def initialize json
      @json      = json
      @files     = []
    end

    def addFile file
      @files << file
    end

    def addFiles files
      @files += files
    end

    def json= json
      @json = json
    end

    def create

      # Check for external resources and load them into /tmp somewhere 
      self.loadExternalFiles

      # Create the manifest, now that we (should) have any external files locally
      manifest = self.createManifest

      # Check pass for necessary files and fields
      self.checkPass manifest

      signature = self.createSignature manifest
      return self.createZip(manifest, signature)
    end

    protected

      def loadExternalFiles

        @tmpdir = Dir.mktmpdir('pk_')

        @files.each_with_index do |file, index|
          name = file.is_a?(Hash) && file.has_key?(:file) ? file[:file] : file
          fetch_remote_file(file, index) if name.match(/^http/)
        end

      end

      def fetch_remote_file(file, index)
        is_hash   = file.is_a?(Hash)
        url       = is_hash ? file[:file] : file
        name      = File.basename( is_hash ? file[:name] : file )
        local     = "#{@tmpdir}/#{name}"

        open(local, 'wb') do |file|
          file << open(url).read
        end
        
        @files[index] = (is_hash) ? { :name => file[:name], :file => local } : local

      end


      def checkPass manifest
        # Check for default images
        raise 'Icon missing'      unless manifest.include?('icon.png')
        raise 'Icon@2x missing'   unless manifest.include?('icon@2x.png')
        raise 'Logo missing'      unless manifest.include?('logo.png')
        raise 'Logo@2x missing'   unless manifest.include?('logo@2x.png')

        # Check for developer field in JSON
        raise 'Pass Type Identifier missing' unless @json.include?('passTypeIdentifier')
        raise 'Team Identifier missing' unless @json.include?('teamIdentifier')
        raise 'Serial Number missing' unless @json.include?('serialNumber')
        raise 'Organization Name Identifier missing' unless @json.include?('organizationName')
        raise 'Format Version' unless @json.include?('formatVersion')
        raise 'Description' unless @json.include?('description')
      end

      def createManifest
        sha1s = {}
        sha1s['pass.json'] = Digest::SHA1.hexdigest @json

        @files.each do |file|
          if file.is_a?(Hash)

            # Is this straight up content from memory?
            if file.has_key?(:content)
              sha1s[file[:name]] = Digest::SHA1.hexdigest file[:content]
            elsif file.has_key?(:file)
              sha1s[file[:name]] = Digest::SHA1.file(file[:file]).hexdigest
            end
          else
            sha1s[File.basename(file)] = Digest::SHA1.file(file).hexdigest
          end
        end

        return sha1s.to_json
      end

      def createSignature manifest
        p12   = OpenSSL::PKCS12.new File.read(Passbook.p12_cert), Passbook.p12_password

        # Add the WWDR certificate to the mix to verify authenticity chain
        wwdr  = OpenSSL::X509::Certificate.new File.read(Passbook.wwdc_cert)

        pk7   = OpenSSL::PKCS7.sign p12.certificate, p12.key, manifest.to_s, [wwdr], OpenSSL::PKCS7::BINARY | OpenSSL::PKCS7::DETACHED
        data  = OpenSSL::PKCS7.write_smime pk7

        str_debut = "filename=\"smime.p7s\"\n\n"
        data = data[data.index(str_debut)+str_debut.length..data.length-1]
        str_end = "\n\n------"
        data = data[0..data.index(str_end)-1]

        return Base64.decode64(data)
      end

      def createZip manifest, signature
        t = Tempfile.new("pass.pkpass")

        Zip::ZipOutputStream.open(t.path) do |z|
          z.put_next_entry 'pass.json'
          z.print @json
          z.put_next_entry 'manifest.json'
          z.print manifest
          z.put_next_entry 'signature'
          z.print signature

          @files.each do |file|
            if file.is_a?(Hash)

              if file.has_key?(:content)
                z.put_next_entry file[:name]
                z.print file[:content]
              elsif file.has_key?(:file)
                z.put_next_entry File.basename(file[:name])
                z.print IO.read(file[:file])
              end

            else
              z.put_next_entry File.basename(file)
              z.print IO.read(file)
            end
          end
        end
        path = t.path

        t.close

        # Clear out the tmpfile
        FileUtils.remove_entry_secure @tmpdir

        # Return the path to the zipfile
        return path
      end
  end
end