#pragma once
namespace {
void ReviewBudgetRecovery()
{
    ++groups;
    for(unsigned mode=0;mode<5;++mode) {
        MountContext c; c.args.encrypted.enabled=true;c.args.readonly=true;
        c.encrypted=std::make_unique<enc::State>(); auto& s=*c.encrypted;
        auto source=std::make_shared<RuntimeSource>();
        if(mode==0) {source->limits.reads=1;source->limits.read_bytes=512;}
        if(mode==1) source->limits.materialized_bytes=12000;
        s.session=OpenRuntime(source,true,s.cancelled);
        CHECK(s.session->GetNamespaceInfo(s.names)==E::None);
        FSP_FILE_SYSTEM fs{};fs.UserContext=&c;FSP_FSCTL_FILE_INFO info{};PVOID h=nullptr;
        auto path=std::wstring(mode==0?L"\\Report.txt":L"\\");
        CHECK(ei.Open(&fs,path.data(),0,GENERIC_READ,&h,&info)==STATUS_SUCCESS);
        ScopeExit close{[&](){ei.Close(&fs,h);}};
        std::array<std::byte,700> bytes{};ULONG done=99;
        NTSTATUS status;
        if(mode==0) status=ei.Read(&fs,h,bytes.data(),0,700,&done);
        else if(mode==1) {
            auto malformed=L"\\"+std::wstring(100,wchar_t(0xd800));PVOID rejected=nullptr;
            status=ei.Open(&fs,malformed.data(),0,GENERIC_READ,&rejected,&info);CHECK(!rejected);
        } else {
            if(mode==2) source->inner->budget->Refuse("review-source-budget");
            if(mode==3) source->inner->budget=std::make_shared<ApfsReadBudget>(100000,268435456,1000000,268435456);
            if(mode==4) s.session->Cancel();
            status=ei.GetFileInfo(&fs,h,&info);
        }
        if(mode<2) {
            CHECK(status==STATUS_INSUFFICIENT_RESOURCES);
            CHECK(!s.failed && !s.cancelled->load() && !source->inner->budget->Failed());
            CHECK(ei.GetFileInfo(&fs,h,&info)==STATUS_SUCCESS);
            if(mode==0) {
                CHECK(done==0);
                CHECK(ei.Read(&fs,h,bytes.data(),0,10,&done)==STATUS_SUCCESS && done==10);
                for(unsigned i=0;i<10;++i) CHECK(bytes[i]==std::byte((i*7+3)%256));
            }
        } else {
            CHECK(!NT_SUCCESS(status));CHECK(s.cancelled->load());
            CHECK(ei.GetFileInfo(&fs,h,&info)==STATUS_CANCELLED);
        }
    }
}
void ReviewBoundaries()
{
    ++groups;MountContext c;BindMemory(c,EncFixture());
    ScopeExit sd{[&](){LocalFree(c.sd);c.sd=nullptr;}};
    FSP_FILE_SYSTEM fs{};fs.UserContext=&c;FSP_FSCTL_FILE_INFO info{};PVOID root=nullptr,file=nullptr;
    auto root_name=std::wstring(L"\\"),file_name=std::wstring(L"\\Straße");
    CHECK(ei.Open(&fs,root_name.data(),0,GENERIC_READ,&root,&info)==STATUS_SUCCESS);
    CHECK(ei.Open(&fs,file_name.data(),0,GENERIC_READ,&file,&info)==STATUS_SUCCESS);
    ScopeExit close{[&](){ei.Close(&fs,file);ei.Close(&fs,root);}};
    std::array<std::byte,4096> buffer{};ULONG done=0;
    c.api.AddDir=nullptr;
    CHECK(ei.ReadDirectory(&fs,root,nullptr,nullptr,buffer.data(),static_cast<ULONG>(buffer.size()),&done)==STATUS_INVALID_DEVICE_STATE && done==0);
    c.api.AddDir=AddEncDir;c.api.AddStream=nullptr;
    CHECK(ei.GetStreamInfo(&fs,file,buffer.data(),static_cast<ULONG>(buffer.size()),&done)==STATUS_INVALID_DEVICE_STATE && done==0);
    c.api.AddStream=AddEncStream;
    CHECK(ei.GetStreamInfo(&fs,file,buffer.data(),sizeof(FSP_FSCTL_STREAM_INFO),&done)==STATUS_BUFFER_OVERFLOW && done==0);
    CHECK(std::all_of(buffer.begin(),buffer.end(),[](auto b){return b==std::byte{};}));
    CHECK(ei.GetStreamInfo(&fs,file,buffer.data(),static_cast<ULONG>(buffer.size()),&done)==STATUS_SUCCESS);
    unsigned streams=0;
    for(ULONG at=0;at<done;) {auto* row=reinterpret_cast<FSP_FSCTL_STREAM_INFO*>(buffer.data()+at);
        CHECK(row->Size>=sizeof(*row));++streams;at+=row->Size;}
    CHECK(streams==4);
    std::wstring marker;unsigned entries=0;
    for(unsigned round=0;round<8;++round) {
        CHECK(ei.ReadDirectory(&fs,root,nullptr,marker.empty()?nullptr:marker.data(),buffer.data(),
            sizeof(FSP_FSCTL_DIR_INFO)+32,&done)==STATUS_SUCCESS);
        if(!done) break;
        for(ULONG at=0;at<done;) {auto* row=reinterpret_cast<FSP_FSCTL_DIR_INFO*>(buffer.data()+at);
            marker.assign(row->FileNameBuf,(row->Size-sizeof(*row))/sizeof(WCHAR));++entries;at+=row->Size;}
    }
    CHECK(entries==5);CHECK(!c.encrypted->failed && !c.encrypted->cancelled->load());
}
}
