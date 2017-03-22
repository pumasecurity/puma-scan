/* 
 * Copyright(c) 2016 - 2017 Puma Security, LLC (https://www.pumascan.com)
 * 
 * Project Leader: Eric Johnson (eric.johnson@pumascan.com)
 * Lead Developer: Eric Mead (eric.mead@pumascan.com)
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

using System;
using System.Reflection;

using Autofac;

using Microsoft.CodeAnalysis.CSharp.Syntax;

using Puma.Security.Rules.Analyzer.Core;

namespace Puma.Security.Rules//Root namespace to make globally available
{
    //NOTE: this is Service Locator Anti-pattern (i.e not recommended for most applications). Ideally would build the composition root in the startup of the app
    public class PumaApp
    {
        private static PumaApp _pumaApp;

        public static PumaApp Instance => _pumaApp ?? (_pumaApp = new PumaApp());

        private IContainer _container;

        public IContainer Container => _container ?? (_container = this.Initialize());

        private PumaApp()
        {

        }

        private IContainer Initialize()
        {
            var builder = new ContainerBuilder();

            //TODO: fine tune registrations, registering nearly everything both as interface and as concrete
            builder.RegisterAssemblyTypes(Assembly.GetExecutingAssembly())
             .Where(t => t.Namespace.StartsWith("Puma.Security", StringComparison.CurrentCulture))
             .AsImplementedInterfaces()
             .AsSelf();

            var openType = typeof(IExpressionSyntaxAnalyzer<>);
            builder.RegisterGeneric(typeof(BaseExpressionSyntaxAnalyzer<>)).As(openType);
            builder.RegisterType<InvocationExpressionSyntaxAnalyzer>().As<IExpressionSyntaxAnalyzer<InvocationExpressionSyntax>>();
            builder.RegisterType<MemberAccessExpressionSyntaxAnalyzer>().As<IExpressionSyntaxAnalyzer<MemberAccessExpressionSyntax>>();
            builder.RegisterType<BinaryExpressionSyntaxAnalyzer>().As<IExpressionSyntaxAnalyzer<BinaryExpressionSyntax>>();
            builder.RegisterType<ExpressionSyntaxAnalyzer>().As<IExpressionSyntaxAnalyzer<ExpressionSyntax>>();
            builder.Register<Func<object, IExpressionSyntaxAnalyzer>>(c => 
            {
                var context = c.Resolve<IComponentContext>();
                return theObject =>
                {
                    var concreteType =
                        openType.MakeGenericType(theObject.GetType());
                    return (IExpressionSyntaxAnalyzer) context.Resolve(concreteType);
                };
            });
          

            return builder.Build();
        }

        public Func<object, T> GetFuncFactory<T>()
        {
            return PumaApp.Instance.Container.Resolve<Func<object, T>>();
        }
    }
}