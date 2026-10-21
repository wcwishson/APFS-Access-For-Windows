using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using ApfsAccess.Cli;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Tray.Tests;

internal sealed record ImageKeyManagementFormProof(ImageKeyManagementRequest Request,
    ImageKeyManagementReceipt Receipt, bool ViewDetached, bool ViewReceiptPublished,
    bool PendingAtDisposal, int Shown, int Activated);

internal static class ImageKeyManagementProductionDialogProbe
{
    internal static Task<ImageKeyManagementFormProof> RunAsync(ImageKeyManagementRequest selection,
        SupervisedCredentialSet credentials, string privatePipe, CancellationToken token,
        bool disposeDuringRefresh=false)
    {
        if (!FusionControlEndpoint.IsPrivateInstance(privatePipe))
            throw new ArgumentException("A private fixture service is required.");
        var completion=new TaskCompletionSource<ImageKeyManagementFormProof>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread=new Thread(()=>
        {
            try
            {
                WindowsFormsSynchronizationContext.AutoInstall=false;
                var context=new PendingContext();SynchronizationContext.SetSynchronizationContext(context);
                completion.SetResult(Run(context,selection,credentials,privatePipe,token,disposeDuringRefresh));
            }
            catch(Exception failure){completion.SetException(failure);}
        });
        thread.SetApartmentState(ApartmentState.STA);thread.Start();return completion.Task;
    }

    private static ImageKeyManagementFormProof Run(PendingContext context,ImageKeyManagementRequest selection,
        SupervisedCredentialSet credentials,string pipe,CancellationToken token,bool disposeDuringRefresh)
    {
        var current=context.Wait(ImageKeyManagementControlClient.ObserveAsync(selection.Expected,token,pipe));
        if(current!=selection.Expected)throw new InvalidDataException("The selected fixture endpoint changed.");
        ImageKeyManagementRequest? issued=null;ImageKeyManagementReceipt? returned=null;
        var shown=0;var activated=0;
        var refreshing=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseRefresh=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var form=new ImageKeyManagementDialog("Private canonical fixture",current,selection.Action,
            async (request,secret,cancellation)=>
            {
                issued=request;
                using var linked=CancellationTokenSource.CreateLinkedTokenSource(cancellation,token);
                var result=await ImageKeyManagementControlClient.ManageAsync(request,secret,linked.Token,pipe).ConfigureAwait(false);
                if(!result.Success||result.KeyManagementReceipt is not {} receipt||!receipt.Proves(request))
                    throw new IOException("The actual public operation has no complete receipt.");
                current=receipt.After;returned=receipt;return receipt;
            },async cancellation=>
            {
                var observation=ImageKeyManagementControlClient.ObserveAsync(current,cancellation,pipe);
                if(disposeDuringRefresh){refreshing.TrySetResult();await releaseRefresh.Task;}
                return await observation;
            });
        form.Shown+=(_,_)=>++shown;form.Activated+=(_,_)=>++activated;
        var values=(SupervisedCredential[])Field(typeof(SupervisedCredentialSet),"values").GetValue(credentials)!;
        if(credentials.Count!=selection.CredentialCount||values.Length!=selection.CredentialCount)
            throw new InvalidDataException("The fixture credential count differs from the selected action.");
        var first=Get<SecureKeyManagementInput>(form,"first");
        var next=Get<SecureKeyManagementInput>(form,"next");
        var confirmation=Get<SecureKeyManagementInput>(form,"confirmation");
        Populate(first,values[0]);
        if(values.Length==2)Populate(next,values[1]);
        if(selection.Action!=ImageKeyManagementAction.Decrypt)Populate(confirmation,values[^1]);
        credentials.Dispose();
        var confirm=Get<CheckBox>(form,"confirmed");confirm.Checked=true;
        if(!Get<Button>(form,"apply").Enabled)throw new InvalidOperationException("The real form did not admit confirmation.");
        var run=(Task)typeof(ImageKeyManagementDialog).GetMethod("RunAsync",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(form,null)!;
        var pendingAtDisposal=false;
        if(disposeDuringRefresh)
        {
            context.Wait(Task.WhenAny(refreshing.Task,run));
            if(!refreshing.Task.IsCompleted||run.IsCompleted||form.Receipt is not null)
                throw new InvalidOperationException("The real form did not retain its pending refresh.");
            form.Dispose();pendingAtDisposal=!run.IsCompleted;
            releaseRefresh.TrySetResult();
        }
        context.Wait(run);
        if(issued is null||returned is null||!returned.Proves(issued)||returned.After!=current||
            shown!=0||activated!=0||form.Visible||(disposeDuringRefresh
                ? !pendingAtDisposal||!form.IsDisposed||form.Receipt is not null : form.Receipt!=returned))
            throw new InvalidDataException("The production form did not complete the exact public operation.");
        return new(issued,returned,disposeDuringRefresh,form.Receipt is not null,pendingAtDisposal,shown,activated);
    }

    // The fixture arrives through the existing locked credential-frame receiver.
    // Decode directly into unmanaged scratch, then the real secure input; never a managed password string or array.
    private static void Populate(SecureKeyManagementInput input,SupervisedCredential credential)
    {
        var memory=(nint)Field(typeof(SupervisedCredential),"memory").GetValue(credential)!;
        var length=(int)Field(typeof(SupervisedCredential),"length").GetValue(credential)!;
        if(memory==0||length is <=8 or >1032)throw new InvalidDataException("Expired fixture credential owner.");
        var count=MultiByteToWideChar(65001,8,memory+8,length-8,0,0);
        if(count is <=0 or >1024)throw new InvalidDataException("The fixture credential is not strict UTF-8.");
        var bytes=checked(count*2);
        var scratch=Marshal.AllocHGlobal(bytes);
        var locked=false;
        try
        {
            locked=VirtualLock(scratch,(nuint)bytes);
            if(!locked)throw new InvalidOperationException("The fixture credential scratch could not be locked.");
            if(MultiByteToWideChar(65001,8,memory+8,length-8,scratch,count)!=count)
                throw new InvalidDataException("The fixture credential could not enter the secure input.");
            for(var i=0;i<count;++i)
            {
                var value=(char)Marshal.ReadInt16(scratch,i*2);
                if(value=='\0')throw new InvalidDataException("The fixture credential contains a null character.");
                input.Secret.AppendChar(value);
            }
        }
        finally
        {
            for(var i=0;i<count;++i)Marshal.WriteInt16(scratch,i*2,0);
            if(locked)VirtualUnlock(scratch,(nuint)bytes);
            Marshal.FreeHGlobal(scratch);
        }
    }

    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)]
    private static extern int MultiByteToWideChar(uint page,uint flags,nint input,int bytes,nint output,int chars);
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualLock(nint memory,nuint bytes);
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualUnlock(nint memory,nuint bytes);
    private static FieldInfo Field(Type type,string name)=>type.GetField(name,BindingFlags.Instance|BindingFlags.NonPublic)!
        ??throw new MissingFieldException(type.Name,name);
    private static T Get<T>(object owner,string name)=>(T)Field(owner.GetType(),name).GetValue(owner)!;

    private sealed class PendingContext : SynchronizationContext
    {
        private readonly ConcurrentQueue<(SendOrPostCallback Callback,object? State)> pending=new();
        public override void Post(SendOrPostCallback callback,object? state)=>pending.Enqueue((callback,state));
        internal T Wait<T>(Task<T> task){Wait((Task)task);return task.GetAwaiter().GetResult();}
        internal void Wait(Task task)
        {
            while(!task.IsCompleted)
            {
                while(pending.TryDequeue(out var item))item.Callback(item.State);
                Thread.Sleep(1);
            }
            task.GetAwaiter().GetResult();
        }
    }
}
